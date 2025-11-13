"""STIX synchronizer for PortSpoofPro OpenCTI integration."""

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pycti import (OpenCTIApiClient, OpenCTIConnectorHelper,
                   ThreatActorIndividual, Identity as PyctiIdentity)
from stix2 import (AttackPattern, Bundle, Indicator, Infrastructure,
                   IPv4Address, IPv6Address, NetworkTraffic, ObservedData, Relationship,
                   Report, Sighting, ThreatActor, Tool, Identity, TLP_WHITE)
# Import for deterministic UUID generation (same approach as pycti uses)
from stix2.canonicalization.Canonicalize import canonicalize

# Import constants and utilities
from constants import (ATTACK_PREFIX, AUTHOR_DESCRIPTION, AUTHOR_NAME,
                       BEHAVIOR_PREFIX, CONNECTOR_CONFIDENCE_LEVEL_DEFAULT,
                       CONNECTOR_LOG_LEVEL_DEFAULT, CONNECTOR_NAME_DEFAULT,
                       CONNECTOR_QUEUE_PROTOCOL_DEFAULT,
                       CONNECTOR_SCOPE_DEFAULT, CONNECTOR_TYPE_DEFAULT,
                       ENVIRONMENT, FINGERPRINT_PREFIX,
                       MAX_BUNDLE_SIZE_DEFAULT,
                       MAX_STRATEGIC_TARGET_RELATIONSHIPS, MAX_TARGET_IPS_FOR_GRAPH,
                       OPENCTI_NAMESPACE, OPENCTI_SSL_VERIFY_DEFAULT,
                       SESSION_SOURCE_NAME, TECHNIQUE_PREFIX,
                       THREAT_ACTOR_SOURCE_NAME, TLP_CLEAR_STIX_ID,
                       TOOL_SOURCE_NAME)
from helpers import (aggregate_detection_attributes, build_external_reference,
                     build_session_external_references,
                     calculate_opencti_score, calculate_port_scan_metrics,
                     extract_attack_types_from_detections,
                     extract_behaviors_from_detections,
                     extract_techniques_from_detections,
                     extract_tools_from_detections, generate_labels,
                     map_threat_level, parse_iso_datetime, safe_get_float,
                     safe_get_int, safe_get_string)
from validation import (ValidationError, validate_intelligence_data,
                        validate_session_state)

def generate_deterministic_stix_id(object_type: str, properties: dict) -> str:
    """
    Generate deterministic STIX ID using uuid5 for automatic deduplication.

    Args:
        object_type: STIX object type (e.g., "threat-actor")
        properties: Dictionary of properties to use for ID generation

    Returns:
        Deterministic STIX ID in format: {object_type}--{uuid5}
    """
    # Canonicalize properties to ensure consistent JSON representation
    canonical_data = canonicalize(properties, utf8=False)

    # Generate UUID v5 using OpenCTI namespace
    deterministic_uuid = str(uuid.uuid5(OPENCTI_NAMESPACE, canonical_data))

    return f"{object_type}--{deterministic_uuid}"


def generate_tool_stix_id(tool_name: str) -> str:
    """
    Generate deterministic STIX ID for Tool objects.

    Uses UUID5 with tool name to ensure the same tool always gets the same ID
    across all sessions, enabling automatic reuse in OpenCTI.

    Args:
        tool_name: Tool name (e.g., "nmap", "masscan")

    Returns:
        Deterministic Tool STIX ID (e.g., "tool--a1b2c3...")
    """
    from constants import PORTSPOOF_TOOL_NAMESPACE_PREFIX

    namespace_key = f"{PORTSPOOF_TOOL_NAMESPACE_PREFIX}-{tool_name.lower()}"
    deterministic_uuid = str(uuid.uuid5(OPENCTI_NAMESPACE, namespace_key))

    return f"tool--{deterministic_uuid}"


def generate_attack_pattern_stix_id(pattern_type: str, name: str) -> str:
    """
    Generate deterministic STIX ID for AttackPattern objects.

    Supports techniques, behaviors, attacks, and MITRE TTPs with separate namespaces
    to avoid collisions.

    Args:
        pattern_type: "technique", "behavior", "attack", or "mitre"
        name: Pattern name (e.g., "syn_scan") or MITRE TTP ID (e.g., "T1595.001")

    Returns:
        Deterministic AttackPattern STIX ID (e.g., "attack-pattern--x1y2z3...")
    """
    from constants import (
        PORTSPOOF_TECHNIQUE_NAMESPACE_PREFIX,
        PORTSPOOF_BEHAVIOR_NAMESPACE_PREFIX,
        PORTSPOOF_ATTACK_NAMESPACE_PREFIX,
        PORTSPOOF_MITRE_TTP_NAMESPACE_PREFIX,
    )

    # Select namespace prefix based on pattern type
    if pattern_type == "technique":
        namespace_prefix = PORTSPOOF_TECHNIQUE_NAMESPACE_PREFIX
    elif pattern_type == "behavior":
        namespace_prefix = PORTSPOOF_BEHAVIOR_NAMESPACE_PREFIX
    elif pattern_type == "attack":
        namespace_prefix = PORTSPOOF_ATTACK_NAMESPACE_PREFIX
    elif pattern_type == "mitre":
        namespace_prefix = PORTSPOOF_MITRE_TTP_NAMESPACE_PREFIX
    else:
        logging.warning(f"Unknown pattern_type '{pattern_type}', using technique namespace")
        namespace_prefix = PORTSPOOF_TECHNIQUE_NAMESPACE_PREFIX

    namespace_key = f"{namespace_prefix}-{name.lower()}"
    deterministic_uuid = str(uuid.uuid5(OPENCTI_NAMESPACE, namespace_key))

    return f"attack-pattern--{deterministic_uuid}"


def add_empty_where_sighted_refs(bundle_json: str) -> str:
    """
    Workaround for pycti bug - add empty where_sighted_refs to Sighting objects.

    Args:
        bundle_json: Serialized STIX bundle JSON

    Returns:
        Modified bundle JSON with empty where_sighted_refs
    """
    import json

    try:
        bundle_dict = json.loads(bundle_json)

        # Fix Sighting objects that are missing where_sighted_refs
        if "objects" in bundle_dict:
            for obj in bundle_dict["objects"]:
                if obj.get("type") == "sighting" and "where_sighted_refs" not in obj:
                    obj["where_sighted_refs"] = []

        return json.dumps(bundle_dict)
    except Exception as e:
        logging.warning(f"Failed to add where_sighted_refs workaround: {e}")
        return bundle_json


def build_config_from_env() -> Dict[str, Any]:
    """
    Build full OpenCTI Connector config from minimal environment variables.

    Required environment variables:
    - OPENCTI_URL: Customer's OpenCTI instance URL
    - OPENCTI_TOKEN: Customer's OpenCTI API token

    All other settings use sensible defaults (hardcoded).

    Returns:
        Complete config dict for OpenCTIConnectorHelper
    """
    opencti_url = os.getenv("OPENCTI_URL")
    opencti_token = os.getenv("OPENCTI_TOKEN")

    if not opencti_url or not opencti_token:
        raise ValueError(
            "Missing required environment variables: OPENCTI_URL and OPENCTI_TOKEN must be set"
        )

    # Generate unique connector ID (one per container/instance)
    connector_id = f"portspoof-pro-{uuid.uuid4()}"

    # Queue protocol: api (HTTP API for SaaS) or amqp (RabbitMQ for self-hosted)
    queue_protocol = os.getenv("CONNECTOR_QUEUE_PROTOCOL", "api")

    # SSL verification (secure by default)
    ssl_verify_env = os.getenv("OPENCTI_SSL_VERIFY", str(OPENCTI_SSL_VERIFY_DEFAULT))
    ssl_verify = ssl_verify_env.lower() in ("true", "1", "yes")

    return {
        "opencti": {
            "url": opencti_url,
            "token": opencti_token,
            "ssl_verify": ssl_verify,
        },
        "connector": {
            "id": connector_id,
            "type": "EXTERNAL_IMPORT",
            "name": "PortSpoofPro",
            "scope": "Threat-Actor,Observed-Data,IPv4-Addr,IPv6-Addr,Tool,Attack-Pattern,Infrastructure,Report,Relationship,Sighting",
            "confidence_level": 85,  # High confidence (deception network = ground truth)
            "log_level": "info",
            "queue_protocol": queue_protocol,  # HTTP API mode for SaaS platforms
        },
        "portspoof": {
            "enable_auto_sync": True,
            "max_bundle_size": 1000,
            "max_target_ips": 10,
        },
    }


class IntelligenceExtractor:
    """
    Extracts threat intelligence from session state using pattern-based detection matching.
    """

    @staticmethod
    def extract(state: dict) -> dict:
        """
        Extract all intelligence from full state.

        Returns:
        {
            'detected_tools': [],      # From fingerprint:*
            'techniques': [],          # From technique:*
            'behaviors': [],           # From behavior:*
            'attack_types': [],        # From attack:*
            'scan_patterns': {},       # Extracted recon patterns
            'evidence_attributes': {}, # All 17+ attributes
        }
        """
        intelligence = {
            "detected_tools": [],
            "techniques": [],
            "behaviors": [],
            "attack_types": [],
            "scan_patterns": {},
            "evidence_attributes": {},
        }

        # Extract from detection chain
        for detection in state.get("full_detection_chain", []):
            name = detection.get("name", "")
            attrs = detection.get("attributes", {})

            # Extract tool fingerprints
            if name.startswith("fingerprint:"):
                tool_name = name.replace("fingerprint:", "")
                if tool_name not in intelligence["detected_tools"]:
                    intelligence["detected_tools"].append(tool_name)

            # Extract techniques
            elif name.startswith("technique:"):
                technique_name = name.replace("technique:", "")
                if technique_name not in intelligence["techniques"]:
                    intelligence["techniques"].append(technique_name)

            # Extract behaviors
            elif name.startswith("behavior:"):
                behavior_name = name.replace("behavior:", "")
                if behavior_name not in intelligence["behaviors"]:
                    intelligence["behaviors"].append(behavior_name)

                # Extract specific scan patterns
                if "recon" in behavior_name or "scan" in behavior_name:
                    intelligence["scan_patterns"][behavior_name] = True

            # Extract attack types
            elif name.startswith("attack:"):
                attack_type = name.replace("attack:", "")
                if attack_type not in intelligence["attack_types"]:
                    intelligence["attack_types"].append(attack_type)

            # Aggregate ALL attributes (generic, no hardcoding)
            for attr_name, attr_value in attrs.items():
                # For numeric attributes, keep the max value
                if isinstance(attr_value, (int, float)):
                    intelligence["evidence_attributes"][attr_name] = max(
                        intelligence["evidence_attributes"].get(attr_name, 0),
                        attr_value,
                    )
                # For string attributes, keep the latest
                else:
                    intelligence["evidence_attributes"][attr_name] = attr_value

        return intelligence


class DomainObjectManager:
    """Manages creation of Domain Objects (Tools, AttackPatterns) and their relationships."""

    @staticmethod
    def create_tool_objects(
        detected_tools: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[Tool]:
        """
        Create Tool objects from detected tool names.

        Uses deterministic UUIDs to enable automatic reuse across sessions.

        Args:
            detected_tools: List of tool names (e.g., ["nmap", "masscan"])
            created_by_ref: Reference to connector identity
            marking_refs: TLP marking references

        Returns:
            List of Tool STIX objects
        """
        tools = []

        for tool_name in detected_tools:
            # Normalize tool name
            normalized_name = tool_name.lower().strip()
            if not normalized_name:
                continue

            # Generate deterministic STIX ID
            tool_id = generate_tool_stix_id(normalized_name)

            # Create Tool object with proper capitalization for display
            display_name = normalized_name.capitalize()

            tool = Tool(
                id=tool_id,
                name=display_name,
                description=f"Scanning tool detected by PortSpoofPro: {display_name}",
                labels=["portspoof-pro", f"fingerprint:{normalized_name}"],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )

            tools.append(tool)

        return tools

    @staticmethod
    def create_technique_attack_patterns(
        techniques: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[AttackPattern]:
        """
        Create AttackPattern objects for scan techniques.

        Uses deterministic UUIDs to enable automatic reuse across sessions.

        Args:
            techniques: List of technique names (e.g., ["syn_scan", "fin_scan"])
            created_by_ref: Reference to connector identity
            marking_refs: TLP marking references

        Returns:
            List of AttackPattern STIX objects
        """
        patterns = []

        for technique_name in techniques:
            # Normalize technique name
            normalized_name = technique_name.lower().strip()
            if not normalized_name:
                continue

            # Generate deterministic STIX ID
            pattern_id = generate_attack_pattern_stix_id("technique", normalized_name)

            # Create display name (e.g., "syn_scan" -> "SYN Scan")
            display_name = normalized_name.replace("_", " ").title()

            pattern = AttackPattern(
                id=pattern_id,
                name=display_name,
                description=f"Port scanning technique detected by PortSpoofPro: {display_name}",
                labels=["portspoof-pro", f"technique:{normalized_name}"],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )

            patterns.append(pattern)

        return patterns

    @staticmethod
    def create_behavior_attack_patterns(
        behaviors: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[AttackPattern]:
        """
        Create AttackPattern objects for behavioral patterns.

        Uses deterministic UUIDs to enable automatic reuse across sessions.

        Args:
            behaviors: List of behavior names (e.g., ["high_velocity", "persistent_activity"])
            created_by_ref: Reference to connector identity
            marking_refs: TLP marking references

        Returns:
            List of AttackPattern STIX objects
        """
        patterns = []

        for behavior_name in behaviors:
            # Normalize behavior name
            normalized_name = behavior_name.lower().strip()
            if not normalized_name:
                continue

            # Generate deterministic STIX ID
            pattern_id = generate_attack_pattern_stix_id("behavior", normalized_name)

            # Create display name (e.g., "high_velocity" -> "High Velocity")
            display_name = normalized_name.replace("_", " ").title()

            pattern = AttackPattern(
                id=pattern_id,
                name=display_name,
                description=f"Behavioral pattern detected by PortSpoofPro: {display_name}",
                labels=["portspoof-pro", f"behavior:{normalized_name}"],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )

            patterns.append(pattern)

        return patterns

    @staticmethod
    def create_attack_attack_patterns(
        attack_types: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[AttackPattern]:
        """
        Create AttackPattern objects for attack-level detections.

        Uses deterministic UUIDs to enable automatic reuse across sessions.

        Args:
            attack_types: List of attack names (e.g., ["udp_flood_probing", "service_brute_force"])
            created_by_ref: Reference to connector identity
            marking_refs: TLP marking references

        Returns:
            List of AttackPattern STIX objects
        """
        patterns = []

        for attack_name in attack_types:
            # Normalize attack name
            normalized_name = attack_name.lower().strip()
            if not normalized_name:
                continue

            # Generate deterministic STIX ID
            pattern_id = generate_attack_pattern_stix_id("attack", normalized_name)

            # Create display name (e.g., "udp_flood_probing" -> "UDP Flood Probing")
            display_name = normalized_name.replace("_", " ").title()

            pattern = AttackPattern(
                id=pattern_id,
                name=display_name,
                description=f"Attack pattern detected by PortSpoofPro: {display_name}",
                labels=["portspoof-pro", f"attack:{normalized_name}"],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )

            patterns.append(pattern)

        return patterns

    @staticmethod
    def create_mitre_attack_patterns(
        mitre_ttp_ids: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[AttackPattern]:
        """
        Create AttackPattern objects for MITRE ATT&CK TTPs.

        Uses deterministic UUIDs based on TTP ID. Fully dynamic - no hardcoding needed.

        Args:
            mitre_ttp_ids: List of MITRE TTP IDs (e.g., ["T1595.001", "T1046"])
            created_by_ref: Reference to connector identity
            marking_refs: TLP marking references

        Returns:
            List of AttackPattern STIX objects
        """
        from helpers import format_mitre_ttp_url, format_mitre_ttp_name
        from constants import MITRE_ATTACK_SOURCE_NAME

        patterns = []

        for ttp_id in mitre_ttp_ids:
            # Normalize TTP ID
            normalized_ttp_id = ttp_id.upper().strip()
            if not normalized_ttp_id:
                continue

            # Generate deterministic STIX ID based on TTP ID
            pattern_id = generate_attack_pattern_stix_id("mitre", normalized_ttp_id)

            # Generate display name and URL
            display_name = format_mitre_ttp_name(normalized_ttp_id)
            ttp_url = format_mitre_ttp_url(normalized_ttp_id)

            pattern = AttackPattern(
                id=pattern_id,
                name=display_name,
                description=f"MITRE ATT&CK technique {normalized_ttp_id} detected by PortSpoofPro",
                labels=["portspoof-pro", f"mitre-ttp:{normalized_ttp_id}"],
                external_references=[
                    {
                        "source_name": MITRE_ATTACK_SOURCE_NAME,
                        "external_id": normalized_ttp_id,
                        "url": ttp_url,
                    }
                ],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )

            patterns.append(pattern)

        return patterns

    @staticmethod
    def create_threat_actor_relationships(
        threat_actor_id: str,
        tools: List[Tool],
        attack_patterns: List[AttackPattern],
        marking_refs: List[str],
    ) -> List[Relationship]:
        """
        Create 'uses' relationships between ThreatActorIndividual and Domain Objects.

        Args:
            threat_actor_id: STIX ID of ThreatActorIndividual
            tools: List of Tool objects
            attack_patterns: List of AttackPattern objects
            marking_refs: TLP marking references

        Returns:
            List of Relationship STIX objects
        """
        relationships = []

        # ThreatActorIndividual -> uses -> Tool
        for tool in tools:
            rel = Relationship(
                relationship_type="uses",
                source_ref=threat_actor_id,
                target_ref=tool.id,
                description=f"Threat actor uses {tool.name}",
                object_marking_refs=marking_refs,
            )
            relationships.append(rel)

        # ThreatActorIndividual -> uses -> AttackPattern
        for pattern in attack_patterns:
            rel = Relationship(
                relationship_type="uses",
                source_ref=threat_actor_id,
                target_ref=pattern.id,
                description=f"Threat actor employs {pattern.name}",
                object_marking_refs=marking_refs,
            )
            relationships.append(rel)

        return relationships


class IpObservableManager:
    """Manages IPv4/IPv6 Address observables (STIX2 library)."""

    @staticmethod
    def create_source_ip_observable(
        source_ip: str,
        session_id: str,
        state: dict,
        intelligence: dict,
        created_by_ref: str,
        marking_refs: List[str],
    ):
        """Create IPv4 or IPv6 Address observable for attacker IP with queryable labels."""
        from helpers import (
            calculate_time_wasted_minutes,
            calculate_duration_minutes,
            calculate_port_volume_category,
            calculate_port_scan_metrics,
            format_port_list_by_technique,
        )

        # Extract metrics from LATEST session (for primary queries in Observables tab)
        # Multi-session note: These metrics get overwritten on new sessions (stateless design)
        # Full history is preserved in ObservedData objects
        risk_score = state.get("risk_score", 0)
        alert_level = state.get("alert_level", 0)
        total_ports_seen = state.get("total_ports_seen", 0)
        total_hosts_probed = state.get("total_hosts_probed", 0)
        time_wasted_secs = state.get("total_attacker_time_wasted_secs", 0)
        duration_secs = state.get("total_session_duration_secs", 0)
        probed_ports_detail = state.get("full_probed_ports") or {}

        # Calculate queryable metrics
        time_wasted_mins = calculate_time_wasted_minutes(time_wasted_secs)
        duration_mins = calculate_duration_minutes(duration_secs)
        port_volume = calculate_port_volume_category(total_ports_seen)
        attacker_score = calculate_opencti_score(alert_level)

        # Calculate detailed port scan metrics
        port_scan_metrics = calculate_port_scan_metrics(probed_ports_detail)
        tcp_ports_total = (
            port_scan_metrics["syn_ports"]
            + port_scan_metrics["fin_ports"]
            + port_scan_metrics["null_ports"]
            + port_scan_metrics["xmas_ports"]
            + port_scan_metrics["ack_ports"]
            + port_scan_metrics["full_connect_ports"]
        )

        # Check event type for label filtering (prevent accumulation)
        event_type = state.get("last_event_type", "")
        is_final_event = (event_type == "scanner_session_ended")

        # Build labels: low-cardinality shown during session, high-cardinality on final event
        labels = [
            "portspoof-pro",
            "attacker-ip",
            "network-reconnaissance",
        ]

        # Low-cardinality labels (max 1-4 values, acceptable accumulation)
        labels.extend([
            f"threat:{map_threat_level(alert_level).lower()}",
            f"port-volume:{port_volume}",
        ])

        # High-cardinality metrics (only on scanner_session_ended to prevent accumulation)
        if is_final_event:
            labels.extend([
                f"risk-score:{int(risk_score)}",
                f"ports-scanned:{total_ports_seen}",
                f"hosts-probed:{total_hosts_probed}",
                f"tcp-ports:{tcp_ports_total}",
                f"udp-ports:{port_scan_metrics['udp_ports']}",
            ])

            # Add time metrics only if non-zero
            if time_wasted_mins > 0:
                labels.append(f"attacker-time-wasted-minutes:{time_wasted_mins}")
            if duration_mins > 0:
                labels.append(f"session-duration-minutes:{duration_mins}")

        # Build description with latest session intelligence
        tools = intelligence.get("detected_tools", [])
        techniques = intelligence.get("techniques", [])
        behaviors = intelligence.get("behaviors", [])
        attack_types = intelligence.get("attack_types", [])

        tools_str = ", ".join(tools) if tools else "None"
        techniques_str = ", ".join(techniques) if techniques else "None"
        behaviors_str = ", ".join(behaviors) if behaviors else "None"
        attacks_str = ", ".join(attack_types) if attack_types else "None"

        # Build time wasted summary (only if non-zero)
        time_summary = (
            f"- Attacker time wasted: {time_wasted_mins} minutes (service emulation delays)\n"
            if time_wasted_mins > 0
            else ""
        )

        description = f"""Malicious IP observed by PortSpoofPro deception platform.

**Latest Session Metrics:**
- {total_hosts_probed} targets probed, {total_ports_seen} ports scanned
- TCP: {tcp_ports_total} ports, UDP: {port_scan_metrics['udp_ports']} ports
{time_summary}
**Latest Intelligence:**
- Tools: {tools_str}
- Techniques: {techniques_str}
- Behaviors: {behaviors_str}
- Attacks: {attacks_str}

**Current Threat Level:** {map_threat_level(alert_level)} (Risk Score: {int(risk_score)}/1000)

**For detailed breakdown:** See the related Observed-Data object for scan techniques, port lists, and evidence attributes.
**For complete forensics:** Query MongoDB session: `{session_id}`
**For TTP analysis:** See ThreatActor graph for complete attack patterns and relationships.
"""

        # Custom properties: always include for real-time visibility
        custom_properties = {
            "x_opencti_score": attacker_score,
            "x_opencti_description": description.strip(),
            # Real-time metrics (visible during active session)
            "x_portspoof_tcp_ports": tcp_ports_total,
            "x_portspoof_udp_ports": port_scan_metrics['udp_ports'],
            "x_portspoof_risk_score": int(risk_score),
            "x_portspoof_ports_scanned": total_ports_seen,
            "x_portspoof_hosts_probed": total_hosts_probed,
            # Low-cardinality metrics (for consistency with labels)
            "x_portspoof_threat_level": map_threat_level(alert_level).lower(),
            "x_portspoof_port_volume_category": port_volume,
        }

        # Add optional time metrics if non-zero
        if time_wasted_mins > 0:
            custom_properties["x_portspoof_time_wasted_minutes"] = time_wasted_mins
        if duration_mins > 0:
            custom_properties["x_portspoof_duration_minutes"] = duration_mins

        if ":" in source_ip:
            return IPv6Address(
                value=source_ip,
                created_by_ref=created_by_ref,
                labels=labels,
                object_marking_refs=marking_refs,
                custom_properties=custom_properties,
                allow_custom=True,
            )
        else:
            return IPv4Address(
                value=source_ip,
                created_by_ref=created_by_ref,
                labels=labels,
                object_marking_refs=marking_refs,
                custom_properties=custom_properties,
                allow_custom=True,
            )

    @staticmethod
    def create_target_ip_observables(
        target_ips: List[str],
        max_targets: int,
        session_id: str,
        state: dict,
        created_by_ref: str,
        marking_refs: List[str],
    ):
        """Create IPv4/IPv6 Address observables for target hosts (minimal labels)."""
        observables = []

        description = f"Target host scanned by attacker. See ObservedData for scan details."

        labels = [
            "portspoof-pro",
            "victim",
            "target-host",
            f"session:{session_id[:8]}",
        ]

        custom_properties = {
            "x_opencti_description": description,
        }

        for ip in target_ips[:max_targets]:
            if ":" in ip:
                observables.append(
                    IPv6Address(
                        value=ip,
                        created_by_ref=created_by_ref,
                        labels=labels,
                        object_marking_refs=marking_refs,
                        custom_properties=custom_properties,
                        allow_custom=True,
                    )
                )
            else:
                observables.append(
                    IPv4Address(
                        value=ip,
                        created_by_ref=created_by_ref,
                        labels=labels,
                        object_marking_refs=marking_refs,
                        custom_properties=custom_properties,
                        allow_custom=True,
                    )
                )

        if len(target_ips) > max_targets:
            logging.debug(
                f"Limited target IPs from {len(target_ips)} to {max_targets} observables"
            )

        return observables

    @staticmethod
    def create_network_traffic_objects(
        source_ip_observable,
        target_ip_observables: List,
        session_id: str,
        state: dict,
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List:
        """
        Create minimal Network-Traffic objects as relationship markers only.

        Creates ONE Network-Traffic object per (attacker → target) pair with NO port/technique data.
        Port data is cumulative across all targets, so it's stored in ObservedData instead.

        Args:
            source_ip_observable: Source IP observable
            target_ip_observables: List of target IP observables
            session_id: Session ID
            state: Full session state
            created_by_ref: Reference to connector identity
            marking_refs: TLP marking references

        Returns:
            List of minimal Network-Traffic STIX objects
        """
        network_traffic_objects = []
        total_targets = len(target_ip_observables)

        # Calculate risk score once
        risk_score = state.get("risk_score", 0)
        network_traffic_score = min(100, int(risk_score / 10))

        for idx, target_ip_obs in enumerate(target_ip_observables, start=1):
            # UI display alias: "187.202.34.109 → 10.0.1.1"
            alias = f"{source_ip_observable.value} → {target_ip_obs.value}"

            # Minimal description - points to ObservedData for details
            description = (
                f"Network reconnaissance activity from {source_ip_observable.value} "
                f"targeting {target_ip_obs.value}. This host was one of {total_targets} "
                f"target(s) probed in this session. See ObservedData for complete scan "
                f"intelligence including port details and techniques."
            )

            # Create minimal Network-Traffic object (relationship marker only)
            nt = NetworkTraffic(
                src_ref=source_ip_observable.id,
                dst_ref=target_ip_obs.id,
                protocols=["tcp", "udp"],  # Generic - cannot determine per-target protocols
                created_by_ref=created_by_ref,
                custom_properties={
                    "x_opencti_description": description,
                    "x_opencti_score": network_traffic_score,
                    "x_opencti_aliases": [alias],
                    "labels": [
                        "portspoof-pro",
                        "network-reconnaissance",
                        f"target:{idx}",  # Static position (no coupling to total)
                        f"session:{session_id[:8]}",
                    ]
                },
                object_marking_refs=marking_refs,
                allow_custom=True,
            )
            network_traffic_objects.append(nt)

        logging.info(
            f"Created {len(network_traffic_objects)} Network-Traffic objects "
            f"(relationship markers only - port data in ObservedData)"
        )
        return network_traffic_objects


class ObservedDataManager:
    """
    Manages Observed-Data objects with telemetry in custom properties.
    """

    @staticmethod
    def create_observed_data(
        state: dict,
        intelligence: dict,
        source_ip_observable,
        target_ip_observables: List,
        network_traffic_objects: List,
        created_by_ref: str,
        marking_refs: List[str],
        session_id: str,
        capping_label: Optional[str] = None,
    ):
        """
        Create Observed-Data with queryable labels and evidence custom properties.

        Evidence attributes are stored as x_portspoof_evidence_* for UI filtering.
        """
        from helpers import (
            calculate_time_wasted_minutes,
            calculate_duration_minutes,
            calculate_port_volume_category,
            calculate_port_scan_metrics,
            format_port_list_by_technique,
        )

        try:
            # Build object_refs (links to IP observables and Network-Traffic)
            object_refs = [source_ip_observable.id]
            for target_ip in target_ip_observables:
                object_refs.append(target_ip.id)
            for nt in network_traffic_objects:
                object_refs.append(nt.id)

            # Extract metrics from state
            risk_score = state.get("risk_score", 0)
            alert_level = state.get("alert_level", 0)
            total_ports_seen = state.get("total_ports_seen", 0)
            total_hosts_probed = state.get("total_hosts_probed", 0)
            time_wasted_secs = state.get("total_attacker_time_wasted_secs", 0)
            duration_secs = state.get("total_session_duration_secs", 0)
            # Get sensor fields (always present in new telemetry, may be null/empty for legacy MongoDB docs)
            sensor_id = state.get("sensor_id") or "none"
            sensor_hostname = state.get("sensor_hostname") or "none"

            probed_ports_detail = state.get("full_probed_ports") or {}

            # Calculate queryable metrics
            time_wasted_mins = calculate_time_wasted_minutes(time_wasted_secs)
            duration_mins = calculate_duration_minutes(duration_secs)
            port_volume = calculate_port_volume_category(total_ports_seen)
            normalized_score = min(100, int(risk_score / 10))

            # Calculate detailed port scan metrics
            port_scan_metrics = calculate_port_scan_metrics(probed_ports_detail)
            tcp_ports_total = (
                port_scan_metrics["syn_ports"]
                + port_scan_metrics["fin_ports"]
                + port_scan_metrics["null_ports"]
                + port_scan_metrics["xmas_ports"]
                + port_scan_metrics["ack_ports"]
                + port_scan_metrics["full_connect_ports"]
            )

            # Always include sensor_id in session label (use "none" if missing/empty for legacy docs)
            session_label = f"session:{sensor_id}:{session_id}"

            # Build queryable labels (ALL queryable in OpenCTI)
            labels = [
                "portspoof-pro",
                "scan-intelligence",
                session_label,  # Includes sensor context when available
                f"threat:{map_threat_level(alert_level).lower()}",
                f"risk-score:{int(risk_score)}",
                f"ports-scanned:{total_ports_seen}",
                f"hosts-probed:{total_hosts_probed}",
                f"port-volume:{port_volume}",
                # Detailed scan technique breakdown
                f"tcp-ports:{tcp_ports_total}",
                f"udp-ports:{port_scan_metrics['udp_ports']}",
                f"syn-ports:{port_scan_metrics['syn_ports']}",
                f"fin-ports:{port_scan_metrics['fin_ports']}",
                f"ack-ports:{port_scan_metrics['ack_ports']}",
            ]

            # Add time metrics only if non-zero (no point querying for 0)
            if time_wasted_mins > 0:
                labels.append(f"attacker-time-wasted-minutes:{time_wasted_mins}")
            if duration_mins > 0:
                labels.append(f"session-duration-minutes:{duration_mins}")

            # Add standalone sensor labels (always present)
            labels.append(f"sensor:{sensor_id}")
            labels.append(f"sensor-host:{sensor_hostname}")

            if capping_label:
                labels.append(capping_label)
            description = ObservedDataManager._build_description_summary(
                state, intelligence, time_wasted_mins, duration_mins
            )

            # Build custom properties with evidence attributes
            custom_properties = {
                "x_opencti_description": description,
                "x_opencti_score": normalized_score,
            }

            # Add queryable evidence attributes as custom properties
            # These enable OpenCTI UI filters like "peak_concurrent > 10"
            evidence_attributes = intelligence.get("evidence_attributes", {})

            # Map evidence attributes to x_portspoof_evidence_* custom properties
            evidence_mapping = {
                "peak_concurrent": "x_portspoof_evidence_peak_concurrent",
                "velocity": "x_portspoof_evidence_velocity",
                "connection_count": "x_portspoof_evidence_connection_count",
                "syn_probe_count": "x_portspoof_evidence_syn_probe_count",
                "udp_packets_received": "x_portspoof_evidence_udp_packets_received",
                "udp_unique_ports_probed": "x_portspoof_evidence_udp_unique_ports_probed",
                "session_duration": "x_portspoof_evidence_session_duration",
                "bytes_sent": "x_portspoof_evidence_bytes_sent",
                "interaction_count": "x_portspoof_evidence_interaction_count",
                "destination_host_count": "x_portspoof_evidence_destination_host_count",
                "port_count": "x_portspoof_evidence_port_count",
            }

            for source_key, target_key in evidence_mapping.items():
                if source_key in evidence_attributes:
                    value = evidence_attributes[source_key]
                    # Only add numeric values for proper filtering
                    if isinstance(value, (int, float)):
                        custom_properties[target_key] = value

            # Create Observed-Data with queryable labels and evidence custom properties
            observed_data = ObservedData(
                first_observed=parse_iso_datetime(state.get("session_start_time")),
                last_observed=parse_iso_datetime(state.get("last_activity_time")),
                number_observed=1,
                object_refs=object_refs,
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
                labels=labels,
                external_references=[
                    {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
                ],
                custom_properties=custom_properties,
                allow_custom=True,
            )

            # Count evidence properties (excluding x_opencti_description and x_opencti_score)
            evidence_props_count = len(custom_properties) - 2

            logging.debug(
                f"Created Observed-Data: {observed_data.id} with {len(object_refs)} object_refs, "
                f"{len(labels)} queryable labels, {evidence_props_count} evidence properties"
            )
            return observed_data

        except Exception as e:
            logging.error(f"Failed to create Observed-Data: {e}")
            return None

    @staticmethod
    def _build_description_summary(
        state: dict, intelligence: dict, time_wasted_mins: int, duration_mins: int
    ) -> str:
        """
        Build human-readable summary description for ObservedData.

        This is for human readability only - NOT for data storage.
        All queryable data is in labels.
        """
        from helpers import format_port_list_by_technique

        session_id = state["session_id"]
        source_ip = state.get("source_ip", "unknown")
        risk_score = state.get("risk_score", 0)
        alert_level = state.get("alert_level", 0)
        total_ports_seen = state.get("total_ports_seen", 0)
        total_hosts_probed = state.get("total_hosts_probed", 0)
        sensor_hostname = state.get("sensor_hostname") or "none"
        probed_ports_detail = state.get("full_probed_ports") or {}
        target_hosts = state.get("full_probed_hosts") or []

        # Build tools/techniques summary
        tools = intelligence.get("detected_tools", [])
        techniques = intelligence.get("techniques", [])
        behaviors = intelligence.get("behaviors", [])
        attack_types = intelligence.get("attack_types", [])

        tools_str = ", ".join(tools) if tools else "None"
        techniques_str = ", ".join(techniques) if techniques else "None"
        behaviors_str = ", ".join(behaviors) if behaviors else "None"
        attacks_str = ", ".join(attack_types) if attack_types else "None"

        # Build target list (limit to first 10)
        target_list = "\n".join(f"  {idx+1}. {ip}" for idx, ip in enumerate(target_hosts[:10]))
        if len(target_hosts) > 10:
            target_list += f"\n  ... and {len(target_hosts) - 10} more"

        # Build time metrics (only if non-zero)
        time_wasted_line = (
            f"**Time Wasted:** {time_wasted_mins} minutes (service emulation delays)\n"
            if time_wasted_mins > 0
            else ""
        )
        duration_line = (
            f"**Duration:** {duration_mins} minutes\n" if duration_mins > 0 else ""
        )

        # Build port list section (first 10 ports per technique)
        port_list_str = format_port_list_by_technique(probed_ports_detail, max_ports_per_technique=10)
        port_section = ""
        if port_list_str:
            port_section = f"""
## Port Scanning Details
{port_list_str}

"""

        description = f"""# Scan Intelligence Report

**Session ID:** {session_id}
**Source IP:** {source_ip}
**Risk Score:** {risk_score:.0f} / 1000 (Alert Level: {alert_level})
{time_wasted_line}{duration_line}**Sensor:** {sensor_hostname}

## Reconnaissance Summary
- **Targets Probed:** {total_hosts_probed} unique hosts
- **Total Ports Scanned:** {total_ports_seen} unique ports (cumulative across all targets)
- **Scan Techniques:** {len(probed_ports_detail)} methods detected
{port_section}
## Intelligence
- **Detected Tools:** {tools_str}
- **Scan Techniques:** {techniques_str}
- **Behavioral Patterns:** {behaviors_str}
- **Attack Patterns:** {attacks_str}

## Target Infrastructure
{target_list}

**Full port list:** Query MongoDB: `db.sessions.findOne({{"session_id": "{session_id}"}}, {{"full_probed_ports": 1}})`
**Note:** Port data is cumulative across all targets. Individual per-target port mappings are not available in PortSpoofPro's aggregator output.
"""
        return description.strip()

    @staticmethod
    def _map_threat_level(alert_level: int) -> str:
        """Map alert level to threat level string."""
        mapping = {0: "Info", 1: "Suspicious", 2: "High", 3: "Critical"}
        return mapping.get(alert_level, "Unknown")


class StixSynchronizer:
    """
    OpenCTI synchronizer for PortSpoofPro threat intelligence.

    Implements Threat-Actor-centric STIX model with work tracking and bundle-based updates.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize synchronizer with OpenCTI Connector Framework.

        Args:
            config: Configuration dict with 'opencti' and 'connector' sections
        """
        # Create OpenCTI connector helper
        self.helper = OpenCTIConnectorHelper(config)
        self.api = self.helper.api

        logging.info(f"Initialized PortSpoofPro connector: {self.helper.connect_id}")
        logging.info(f"Connector name: {self.helper.connect_name}")
        logging.info(f"Connector type: {self.helper.connect_type}")

        # Get or create author identity and retrieve STIX standard_id
        try:
            identity_dict = self.api.identity.create(
                type="Organization", name=AUTHOR_NAME, description=AUTHOR_DESCRIPTION
            )
            self.author_opencti_id = identity_dict["id"]
            self.author_standard_id = (
                identity_dict.get("standard_id") or identity_dict["id"]
            )
            logging.info(
                f"Author identity: OpenCTI ID={self.author_opencti_id}, STIX ID={self.author_standard_id}"
            )
        except Exception as e:
            logging.error(f"FATAL: Failed to create author identity: {e}")
            raise

        # Get TLP:CLEAR marking definition from platform (don't create duplicate)
        try:
            markings = self.api.marking_definition.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "definition", "values": ["TLP:CLEAR"]}],
                    "filterGroups": [],
                }
            )
            if markings and len(markings) > 0:
                tlp_clear = markings[0]
                self.tlp_clear_opencti_id = tlp_clear["id"]
                self.tlp_clear_stix_id = tlp_clear.get("standard_id") or tlp_clear["id"]
                logging.info(
                    f"Using existing TLP:CLEAR marking: STIX ID={self.tlp_clear_stix_id}"
                )
            else:
                # Fallback: use well-known TLP:CLEAR standard_id
                self.tlp_clear_stix_id = (
                    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                )
                self.tlp_clear_opencti_id = self.api.marking_definition.read(
                    id=self.tlp_clear_stix_id
                )["id"]
                logging.info(f"Using standard TLP:CLEAR ID: {self.tlp_clear_stix_id}")
        except Exception as e:
            logging.warning(
                f"Failed to query TLP:CLEAR marking: {e}. Using standard ID."
            )
            self.tlp_clear_stix_id = (
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            )
            self.tlp_clear_opencti_id = self.tlp_clear_stix_id  # Fallback, may fail

        # Initialize sub-managers
        self.extractor = IntelligenceExtractor()

        # Cache for tracking which IPs have been seen (for deduplication stats)
        self._seen_threat_actor_ips = set()

        # Statistics tracking
        self.stats = {
            "sessions_synced": 0,
            "threat_actors_created": 0,
            "threat_actors_updated": 0,
            "infrastructures_created": 0,
            "observed_data_created": 0,
            "tools_created": 0,
            "attack_patterns_created": 0,
            "indicators_created": 0,
            "sightings_created": 0,
            "reports_created": 0,
            "relationships_created": 0,
            "api_errors": 0,
        }

    def log_statistics(self):
        """Log current synchronizer statistics."""
        logging.info("=" * 60)
        logging.info("STIX Synchronizer Statistics:")
        logging.info(f"  Sessions synced: {self.stats['sessions_synced']}")
        logging.info(
            f"  Threat Actors created: {self.stats['threat_actors_created']:,}"
        )
        logging.info(
            f"  Threat Actors updated: {self.stats['threat_actors_updated']:,}"
        )
        logging.info(f"  Observed data created: {self.stats['observed_data_created']}")
        logging.info(f"  Tools created: {self.stats['tools_created']}")
        logging.info(
            f"  Attack Patterns created: {self.stats['attack_patterns_created']}"
        )
        logging.info(f"  Indicators created: {self.stats['indicators_created']}")
        logging.info(f"  Sightings created: {self.stats['sightings_created']}")
        logging.info(f"  Reports created: {self.stats['reports_created']}")
        logging.info(f"  Relationships created: {self.stats['relationships_created']}")
        logging.info(f"  API errors: {self.stats['api_errors']}")
        logging.info("=" * 60)

    def sync_session(self, state: dict):
        """
        Synchronize session state to OpenCTI using STIX2 Bundle.

        Creates all STIX objects (Threat-Actor, Observables, Infrastructure, Tools, etc.)
        and sends them as a single bundle with work tracking.
        """
        session_id = state["session_id"]
        source_ip = state["source_ip"]
        event_type = state.get("last_event_type", "unknown")

        logging.info(
            f"Syncing session {session_id} from {source_ip} (event: {event_type})"
        )

        # Initiate work tracking in OpenCTI
        work_id = self._initiate_work(session_id, source_ip)

        bundle_objects = []

        try:
            # Extract intelligence from session state
            intelligence = self.extractor.extract(state)
            logging.debug(
                f"Extracted intelligence: {len(intelligence['detected_tools'])} tools, "
                f"{len(intelligence['techniques'])} techniques"
            )

            # Create Threat-Actor object with deterministic ID
            threat_actor = self._create_threat_actor(state, intelligence, session_id)
            bundle_objects.append(threat_actor)
            self._track_threat_actor_stats(source_ip)

            # Create IP observables and relationships
            ip_objects = self._create_ip_observables_and_relationships(
                state, intelligence, threat_actor, session_id
            )
            bundle_objects.append(ip_objects["source_ip_observable"])
            bundle_objects.extend(ip_objects["target_ip_observables"])
            bundle_objects.extend(ip_objects.get("victim_observables_for_rels", []))  # Add victim IPs for targets relationships
            bundle_objects.extend(ip_objects["network_traffic_objects"])
            bundle_objects.extend(ip_objects["relationships"])

            # Create Indicators with based-on and indicates relationships
            indicator_objects = self._create_indicators_and_relationships(
                state,
                intelligence,
                threat_actor,
                ip_objects["source_ip_observable"],
                session_id,
            )
            bundle_objects.extend(indicator_objects)

            # Create Observed-Data and Sighting
            # Get the indicator we just created (it's in indicator_objects list)
            indicator = indicator_objects[0] if indicator_objects else None
            observed_data = self._create_observed_data_and_sighting(
                state,
                intelligence,
                ip_objects["source_ip_observable"],
                ip_objects["target_ip_observables"],
                ip_objects["network_traffic_objects"],
                threat_actor,
                indicator,
                session_id,
                bundle_objects,
                capping_label=ip_objects.get("capping_label"),  # Pass capping label if victims exceeded threshold
            )

            # Create Tools and Attack Patterns with relationships
            tools_and_patterns = self._create_tools_and_attack_patterns(
                state, intelligence, threat_actor, session_id
            )
            bundle_objects.extend(tools_and_patterns)

            # Create session summary Report if session has ended
            if state.get("last_event_type") == "scanner_session_ended":
                report = self._create_session_report(
                    state, intelligence, bundle_objects, session_id
                )
                if report:
                    bundle_objects.append(report)

            # Send bundle to OpenCTI
            self._send_bundle(bundle_objects, work_id, session_id)

            # Mark work as processed
            self._complete_work(work_id, session_id, source_ip, len(bundle_objects))
            self.stats["sessions_synced"] += 1

        except Exception as e:
            self._handle_sync_error(work_id, session_id, e)
            raise

    def _initiate_work(self, session_id: str, source_ip: str) -> str:
        """Initiate work tracking in OpenCTI."""
        friendly_name = f"PortSpoofPro Session {session_id} ({source_ip})"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        logging.info(f"Initiated work: {work_id}")
        return work_id

    def _create_threat_actor(
        self, state: dict, intelligence: dict, session_id: str
    ) -> ThreatActor:
        """Create Threat-Actor STIX object as Individual (not Group)."""
        source_ip = state["source_ip"]
        event_type = state.get("last_event_type", "")

        # Static labels during session, metrics on scanner_session_ended
        labels = generate_labels(state, intelligence, event_type)

        # Use ThreatActorIndividual ID generator (creates Individual, not Group in OpenCTI)
        threat_actor_id = ThreatActorIndividual.generate_id(
            name=source_ip
        )

        # Build session_id with sensor prefix (matches label format exactly)
        sensor_id = state.get("sensor_id") or "none"
        session_id_with_sensor = f"{sensor_id}:{session_id}"

        custom_properties = {
            "x_portspoof_session_id": session_id_with_sensor,  # Format: sensor:uuid
            "x_portspoof_risk_score": int(state.get("risk_score", 0)),
            "x_portspoof_alert_level": state.get("alert_level", 0),
            "x_portspoof_threat_level": map_threat_level(state.get("alert_level", 0)).lower(),
        }

        return ThreatActor(
            id=threat_actor_id,
            name=source_ip,
            threat_actor_types=["hacker"],
            resource_level="individual",
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            labels=labels,
            description=f"Individual threat actor observed by PortSpoofPro deception platform, identified by source IP {source_ip}.",
            external_references=build_session_external_references(
                session_id,
                additional_refs=[
                    build_external_reference(THREAT_ACTOR_SOURCE_NAME, source_ip)
                ],
            ),
            custom_properties=custom_properties,
            allow_custom=True,
        )

    def _track_threat_actor_stats(self, source_ip: str):
        """Track whether this is a new or updated Threat-Actor."""
        if source_ip in self._seen_threat_actor_ips:
            self.stats["threat_actors_updated"] += 1
            logging.debug(f"Updating existing Threat-Actor for {source_ip}")
        else:
            self.stats["threat_actors_created"] += 1
            self._seen_threat_actor_ips.add(source_ip)
            logging.debug(f"Creating new Threat-Actor for {source_ip}")

    def _create_ip_observables_and_relationships(
        self, state: dict, intelligence: dict, threat_actor: ThreatActor, session_id: str
    ) -> dict:
        """
        Create IP observables and strategic target relationships.

        Target relationships use deterministic IDs, created only on session end.
        Capped at first 10 victims (alphabetically sorted) to limit graph noise.
        """
        source_ip = state["source_ip"]

        source_ip_observable = IpObservableManager.create_source_ip_observable(
            source_ip=source_ip,
            session_id=session_id,
            state=state,
            intelligence=intelligence,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )

        # Only create target relationships on final session event
        target_hosts = state.get("full_probed_hosts", [])
        total_victims = len(target_hosts)
        event_type = state.get("last_event_type", "")
        create_targets_relationships = (event_type == "scanner_session_ended")

        if create_targets_relationships:
            sorted_victims = sorted(target_hosts)
            capped_victims = sorted_victims[:MAX_STRATEGIC_TARGET_RELATIONSHIPS]

            is_capped = total_victims > MAX_STRATEGIC_TARGET_RELATIONSHIPS
            capping_label = f"targets-capped-at:{MAX_STRATEGIC_TARGET_RELATIONSHIPS}" if is_capped else None

            logging.info(
                f"Final session event: Creating targets relationships for {len(capped_victims)} victims "
                f"(total: {total_victims}, capped: {is_capped})"
            )

            target_ip_observables = IpObservableManager.create_target_ip_observables(
                target_ips=capped_victims[:3],
                max_targets=3,
                session_id=session_id,
                state=state,
                created_by_ref=self.author_standard_id,
                marking_refs=[self.tlp_clear_stix_id],
            )
        else:
            capped_victims = []
            capping_label = None

            target_ip_observables = IpObservableManager.create_target_ip_observables(
                target_ips=target_hosts[:3],
                max_targets=3,
                session_id=session_id,
                state=state,
                created_by_ref=self.author_standard_id,
                marking_refs=[self.tlp_clear_stix_id],
            )

            logging.info(
                f"Incremental update ({event_type}): Skipping targets relationships"
            )

        network_traffic_objects = IpObservableManager.create_network_traffic_objects(
            source_ip_observable=source_ip_observable,
            target_ip_observables=target_ip_observables,
            session_id=session_id,
            state=state,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )

        # Create source IP relationship (ThreatActor → IPv4-Addr using related-to per STIX 2.1)
        source_ip_relationship = Relationship(
            relationship_type="related-to",
            source_ref=threat_actor.id,
            target_ref=source_ip_observable.id,
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            description=f"Threat actor identified by source IP address {source_ip}.",
            external_references=[
                {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
            ],
        )
        self.stats["relationships_created"] += 1

        targets_relationships = []
        victim_observables_for_rels = []

        if create_targets_relationships:
            session_start = parse_iso_datetime(state.get("session_start_time"))
            session_end = parse_iso_datetime(state.get("last_activity_time"))

            for victim_ip in capped_victims:
                if ":" in victim_ip:
                    victim_observable = IPv6Address(
                        value=victim_ip,
                        created_by_ref=self.author_standard_id,
                        labels=["portspoof-pro", "victim", "target-host"],
                        object_marking_refs=[self.tlp_clear_stix_id],
                        custom_properties={"x_opencti_description": "Target host scanned by attacker."},
                        allow_custom=True,
                    )
                else:
                    victim_observable = IPv4Address(
                        value=victim_ip,
                        created_by_ref=self.author_standard_id,
                        labels=["portspoof-pro", "victim", "target-host"],
                        object_marking_refs=[self.tlp_clear_stix_id],
                        custom_properties={"x_opencti_description": "Target host scanned by attacker."},
                        allow_custom=True,
                    )
                victim_observables_for_rels.append(victim_observable)

                from stix2.utils import _get_dict
                rel_dict = {
                    "type": "relationship",
                    "relationship_type": "targets",
                    "source_ref": threat_actor.id,
                    "target_ref": victim_observable.id,
                    "external_references": [
                        {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
                    ],
                }
                rel_id = str(uuid.uuid5(OPENCTI_NAMESPACE, canonicalize(_get_dict(rel_dict), utf8=False)))

                target_relationship = Relationship(
                    id=f"relationship--{rel_id}",
                    relationship_type="targets",
                    source_ref=threat_actor.id,
                    target_ref=victim_observable.id,
                    description=f"Targeted victim {victim_ip} during reconnaissance session.",
                    start_time=session_start,
                    stop_time=session_end,
                    created_by_ref=self.author_standard_id,
                    object_marking_refs=[self.tlp_clear_stix_id],
                    external_references=[
                        {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
                    ],
                    allow_custom=True,
                )
                targets_relationships.append(target_relationship)
                self.stats["relationships_created"] += 1

            logging.info(
                f"Created {len(victim_observables_for_rels)} victim IP observables, "
                f"{len(targets_relationships)} 'targets' relationships "
                f"(capped: {is_capped}, total victims: {total_victims})"
            )

        return {
            "source_ip_observable": source_ip_observable,
            "target_ip_observables": target_ip_observables,
            "victim_observables_for_rels": victim_observables_for_rels,
            "network_traffic_objects": network_traffic_objects,
            "relationships": [source_ip_relationship] + targets_relationships,
            "capping_label": capping_label,
        }

    def _create_indicators_and_relationships(
        self,
        state: dict,
        intelligence: dict,
        threat_actor: ThreatActor,
        source_ip_observable,
        session_id: str,
    ) -> List:
        """Create Indicator objects with based-on and indicates relationships."""
        objects = []
        source_ip = state["source_ip"]
        risk_score = state.get("risk_score", 0)
        alert_level = state.get("alert_level", 0)
        labels = generate_labels(state, intelligence)

        # Create Indicator with STIX pattern for malicious source IP
        indicator_pattern = f"[ipv4-addr:value = '{source_ip}']"
        if ":" in source_ip:
            indicator_pattern = f"[ipv6-addr:value = '{source_ip}']"

        indicator_name = f"Malicious IP: {source_ip}"
        indicator_description = f"""Port scanning activity detected by PortSpoofPro deception sensor.

**Risk Score:** {risk_score}/100
**Alert Level:** {alert_level} ({map_threat_level(alert_level)})
**Total Ports Probed:** {state.get('total_ports_seen', 0)}
**Total Hosts Targeted:** {state.get('total_hosts_probed', 0)}
**Session ID:** {session_id}

This indicator represents confirmed malicious activity observed through direct interaction with deception infrastructure.""".strip()

        indicator = Indicator(
            pattern=indicator_pattern,
            pattern_type="stix",
            name=indicator_name,
            description=indicator_description,
            valid_from=parse_iso_datetime(state["session_start_time"]),
            labels=labels,
            confidence=85,  # High confidence - detected on deception infrastructure (ground truth)
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            external_references=build_session_external_references(session_id),
            custom_properties={
                "x_opencti_score": calculate_opencti_score(alert_level),
                "x_opencti_main_observable_type": (
                    "IPv6-Addr" if ":" in source_ip else "IPv4-Addr"
                ),
            },
        )
        objects.append(indicator)
        self.stats["indicators_created"] += 1

        # Create "based-on" relationship: Indicator --> Observable
        # This links the threat intelligence (Indicator) to the raw data (Observable)
        based_on_rel = Relationship(
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=source_ip_observable.id,
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            description=f"Indicator is based on observable {source_ip}.",
            external_references=[
                {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
            ],
        )
        objects.append(based_on_rel)
        self.stats["relationships_created"] += 1

        # Create "indicates" relationship: Indicator --> Threat-Actor
        # This shows what the indicator represents (malicious actor)
        indicates_rel = Relationship(
            relationship_type="indicates",
            source_ref=indicator.id,
            target_ref=threat_actor.id,
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            description=f"Indicator of compromise representing threat actor activity from {source_ip}.",
            external_references=[
                {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
            ],
        )
        objects.append(indicates_rel)
        self.stats["relationships_created"] += 1

        logging.debug(
            f"Created Indicator for {source_ip} with based-on and indicates relationships"
        )

        return objects

    def _create_observed_data_and_sighting(
        self,
        state: dict,
        intelligence: dict,
        source_ip_observable,
        target_ip_observables: List,
        network_traffic_objects: List,
        threat_actor: ThreatActor,
        indicator,
        session_id: str,
        bundle_objects: List,
        capping_label: Optional[str] = None,
    ):
        """Create Observed-Data and Sighting objects with proper references."""
        observed_data = ObservedDataManager.create_observed_data(
            state,
            intelligence,
            source_ip_observable,
            target_ip_observables,
            network_traffic_objects,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
            session_id=session_id,
            capping_label=capping_label,  # Pass capping label if victims exceeded threshold
        )

        if observed_data:
            bundle_objects.append(observed_data)
            self.stats["observed_data_created"] += 1

            # Create Sighting with proper references (following CrowdSec pattern)
            # sighting_of_ref: WHAT was sighted (Indicator, per STIX 2.1 best practices)
            # where_sighted_refs: WHERE the sighting occurred (PortSpoofPro CTI Platform - sensor organization)
            # x_opencti_sighting_of_ref: Links to the Observable (OpenCTI custom property for Observables tab)
            sighting = Sighting(
                sighting_of_ref=indicator.id if indicator else threat_actor.id,
                where_sighted_refs=[self.author_standard_id],  # Sensor organization (Identity)
                observed_data_refs=[observed_data.id],  # Link to evidence
                created_by_ref=self.author_standard_id,
                object_marking_refs=[self.tlp_clear_stix_id],
                count=1,
                first_seen=parse_iso_datetime(state["session_start_time"]),
                last_seen=parse_iso_datetime(state["last_activity_time"]),
                description=f"Malicious IP {state['source_ip']} sighted by PortSpoofPro CTI Platform during session {session_id}.",
                external_references=[
                    {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
                ],
                custom_properties={
                    "x_opencti_sighting_of_ref": source_ip_observable.id,
                },
            )
            bundle_objects.append(sighting)
            self.stats["sightings_created"] += 1

            logging.debug(
                f"Created Sighting of Indicator with x_opencti_sighting_of_ref linking to Observable"
            )

    def _create_tools_and_attack_patterns(
        self,
        state: dict,
        intelligence: dict,
        threat_actor: ThreatActor,
        session_id: str,
    ) -> List:
        """
        Create Tool and AttackPattern objects with 'uses' relationships using DomainObjectManager.

        Uses deterministic UUIDs for automatic deduplication across sessions.
        """
        objects = []

        # Extract intelligence
        detected_tools = intelligence.get("detected_tools", [])
        techniques = intelligence.get("techniques", [])
        behaviors = intelligence.get("behaviors", [])
        attack_types = intelligence.get("attack_types", [])
        mitre_ttps = state.get("full_mitre_ttp_chain", [])

        # Create Tool objects with deterministic UUIDs
        tool_objects = DomainObjectManager.create_tool_objects(
            detected_tools=detected_tools,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(tool_objects)
        self.stats["tools_created"] += len(tool_objects)

        # Create AttackPattern objects for techniques
        technique_patterns = DomainObjectManager.create_technique_attack_patterns(
            techniques=techniques,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(technique_patterns)
        self.stats["attack_patterns_created"] += len(technique_patterns)

        # Create AttackPattern objects for behaviors
        behavior_patterns = DomainObjectManager.create_behavior_attack_patterns(
            behaviors=behaviors,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(behavior_patterns)
        self.stats["attack_patterns_created"] += len(behavior_patterns)

        # Create AttackPattern objects for attack-level detections
        attack_patterns = DomainObjectManager.create_attack_attack_patterns(
            attack_types=attack_types,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(attack_patterns)
        self.stats["attack_patterns_created"] += len(attack_patterns)

        # Create AttackPattern objects for MITRE TTPs (fully dynamic, no hardcoding)
        mitre_patterns = DomainObjectManager.create_mitre_attack_patterns(
            mitre_ttp_ids=mitre_ttps,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(mitre_patterns)
        self.stats["attack_patterns_created"] += len(mitre_patterns)

        # Combine all attack patterns for relationship creation
        all_attack_patterns = (
            technique_patterns + behavior_patterns + attack_patterns + mitre_patterns
        )

        # Create 'uses' relationships between ThreatActorIndividual and all Domain Objects
        relationships = DomainObjectManager.create_threat_actor_relationships(
            threat_actor_id=threat_actor.id,
            tools=tool_objects,
            attack_patterns=all_attack_patterns,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(relationships)
        self.stats["relationships_created"] += len(relationships)

        logging.info(
            f"Created {len(tool_objects)} Tools, {len(all_attack_patterns)} AttackPatterns "
            f"({len(technique_patterns)} techniques, {len(behavior_patterns)} behaviors, "
            f"{len(attack_patterns)} attacks, {len(mitre_patterns)} MITRE TTPs), "
            f"and {len(relationships)} relationships for session {session_id}"
        )

        return objects

    def _create_session_report(
        self, state: dict, intelligence: dict, bundle_objects: List, session_id: str
    ) -> Optional[Report]:
        """Create Report for ended session."""
        object_refs = [obj.id for obj in bundle_objects if hasattr(obj, "id")]
        report = self._create_report_stix2(
            state, intelligence, list(set(object_refs)), session_id
        )
        if report:
            self.stats["reports_created"] += 1
        return report

    def _send_bundle(self, bundle_objects: List, work_id: str, session_id: str):
        """Create and send STIX bundle to OpenCTI."""
        # Add Identity and MarkingDefinition STIX objects to bundle to resolve reference issues

        # Create Identity STIX object for author
        author_identity = Identity(
            id=PyctiIdentity.generate_id(name=AUTHOR_NAME, identity_class="organization"),
            name=AUTHOR_NAME,
            identity_class="organization",
            description=AUTHOR_DESCRIPTION
        )

        # Use built-in TLP:WHITE marking
        tlp_marking = TLP_WHITE

        # Insert Identity and MarkingDefinition at beginning of bundle (CrowdSec pattern)
        bundle_objects_with_refs = [author_identity, tlp_marking] + bundle_objects

        bundle = Bundle(objects=bundle_objects_with_refs, allow_custom=True)
        bundle_json = bundle.serialize()

        # Workaround for pycti bug
        bundle_json = add_empty_where_sighted_refs(bundle_json)

        logging.debug(
            f"Created STIX Bundle with {len(bundle_objects_with_refs)} objects "
            f"(+2 for Identity and Marking, {len(bundle_json)} bytes)"
        )

        # Send bundle with auto-cleanup flag
        self.helper.send_stix2_bundle(
            bundle_json,
            work_id=work_id,
            update=True,
            cleanup_inconsistent_bundle=True,  # Auto-fix bundle inconsistencies
        )
        logging.info(
            f"Successfully sent STIX Bundle for session {session_id} "
            f"({len(bundle_objects_with_refs)} objects including Identity and Marking)"
        )

    def _complete_work(
        self, work_id: str, session_id: str, source_ip: str, object_count: int
    ):
        """Mark work as successfully processed."""
        message = f"Imported session {session_id} from {source_ip} - {object_count} objects created/updated."
        self.helper.api.work.to_processed(work_id, message)
        logging.info(f"Work {work_id} marked as processed")

    def _handle_sync_error(self, work_id: str, session_id: str, error: Exception):
        """Handle synchronization error."""
        self.stats["api_errors"] += 1
        error_message = (
            f"Failed to sync session {session_id}: {type(error).__name__}: {error}"
        )
        try:
            self.helper.api.work.to_processed(work_id, error_message, in_error=True)
        except:
            pass
        logging.error(
            f"Failed to sync session {session_id}: {type(error).__name__}: {error}",
            exc_info=True,
        )

    def _create_report_stix2(
        self,
        state: Dict[str, Any],
        intelligence: Dict[str, Any],
        object_refs: List[str],
        session_id: str,
    ) -> Optional[Report]:
        """
        Create Report STIX object for session summary.

        Args:
            state: Session state dictionary
            intelligence: Extracted intelligence
            object_refs: List of STIX object IDs to reference
            session_id: Session identifier

        Returns:
            Report STIX object or None
        """
        try:
            source_ip = state["source_ip"]
            risk_score = safe_get_int(state, "risk_score", 0)
            alert_level = safe_get_int(state, "alert_level", 0)
            threat_level = map_threat_level(alert_level)

            # Build report summary
            tools_summary = ", ".join(intelligence.get("detected_tools", [])) or "None"
            ttps_summary = ", ".join(state.get("full_mitre_ttp_chain", [])) or "None"

            report_name = f"PortSpoofPro Session Report: {source_ip} ({session_id})"
            report_description = f"""
**PortSpoofPro Session Report**

**Attacker:** {source_ip}
**Session ID:** {session_id}
**Risk Score:** {risk_score}/1000
**Threat Level:** {threat_level}

**Detected Tools:** {tools_summary}
**MITRE ATT&CK TTPs:** {ttps_summary}

**Session Metrics:**
- Total Ports Probed: {safe_get_int(state, 'total_ports_seen', 0)}
- Total Hosts Probed: {safe_get_int(state, 'total_hosts_probed', 0)}
- Session Duration: {safe_get_float(state, 'total_session_duration_secs', 0):.2f} seconds
- Attacker Time Wasted: {safe_get_float(state, 'total_attacker_time_wasted_secs', 0):.2f} seconds

**Detection Summary:**
{len(state.get('full_detection_chain', []))} detection rules triggered

This report aggregates all STIX objects created for this PortSpoofPro session.
""".strip()

            # Create deterministic ID for report
            report_id = generate_deterministic_stix_id(
                "report", {"name": report_name, "session_id": session_id}
            )

            report = Report(
                id=report_id,
                name=report_name,
                description=report_description,
                report_types=["threat-actor"],
                published=parse_iso_datetime(state.get("last_activity_time")),
                object_refs=object_refs,
                created_by_ref=self.author_standard_id,
                object_marking_refs=[self.tlp_clear_stix_id],
                labels=[
                    "portspoof-pro",
                    f"session:{session_id}",
                    f"threat:{threat_level.lower()}",
                    f"env:{ENVIRONMENT}",
                ],
                external_references=build_session_external_references(session_id),
            )

            return report

        except Exception as e:
            logging.error(f"Failed to create Report: {e}")
            return None
