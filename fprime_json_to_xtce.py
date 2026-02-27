#!/usr/bin/env python3
"""
############### DISCLAIMER ##################

The ENTIRETY of this file has been auto-generated
 by GenAI(Claude Opus 4.6)

#############################################
Convert an F´ JSON topology dictionary to an XTCE XML dictionary for YAMCS.

The script produces an XTCE SpaceSystem that contains:

  * Hardcoded base structures that are invariant across F´ deployments:
      * CCSDS Space Packet header (CCSDSPacket)
      * F´ packetized-telemetry header (FpTlmPacket, APID 4)
      * F´ event header (FpEventPacket, APID 2)
      * F´ command framing (FprimeCommand, CCSDSPacket TC)

  * Auto-generated deployment-specific entries:
      * Concrete telemetry packet containers  (from ``telemetryPacketSets``)
      * Concrete event containers              (from ``events``)
      * Concrete command definitions           (from ``commands``)
      * All parameter / argument types required by the above

Usage::

    python fprime_json_to_xtce.py <input.json> [output.xml]
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any
from xml.dom.minidom import parseString
from xml.etree.ElementTree import Element, SubElement, tostring

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
XTCE_NS = "http://www.omg.org/spec/XTCE/20180204"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
SCHEMA_LOC = (
    "http://www.omg.org/spec/XTCE/20180204 "
    "https://www.omg.org/spec/XTCE/20180204/SpaceSystem.xsd"
)

# F´ APID values (from ComCfg.Apid enum)
APID_COMMAND = 0
APID_TELEM = 1
APID_LOG = 2
APID_FILE = 3
APID_PACKETIZED_TLM = 4
APID_DP = 5


def safe_name(name: str) -> str:
    """Convert F´ qualified names (dot-separated) to XTCE-safe names ('>' separator)."""
    return name.replace(".", ">")


def short_name(qualified: str) -> str:
    """Extract the short name from a qualified F´ name.

    ``CdhCore.cmdDisp.CMD_NO_OP`` → ``CMD_NO_OP``
    ``CdhCore.cmdDisp.OpCodeRegistered`` → ``OpCodeRegistered``
    """
    return qualified.rsplit(".", 1)[-1]


def qual_name_underscore(qualified: str) -> str:
    """Convert a qualified F´ name to an underscore-separated identifier.

    ``CdhCore.cmdDisp.OpCodeRegistered`` → ``CdhCore_cmdDisp_OpCodeRegistered``
    ``DataProducts.dpCat.FileOpenError``  → ``DataProducts_dpCat_FileOpenError``
    """
    return qualified.replace(".", "_")


def hex_opcode(value: int) -> str:
    """Format an integer as ``0x...`` hex string."""
    return f"0x{value:X}"


# ---------------------------------------------------------------------------
# Type resolver – chases ``qualifiedIdentifier`` and ``alias`` references
# ---------------------------------------------------------------------------
class TypeResolver:
    """Resolves F´ JSON type references to concrete type info."""

    def __init__(self, type_definitions: list[dict]):
        self.type_map: dict[str, dict] = {}
        for td in type_definitions:
            qn = td.get("qualifiedName")
            if qn:
                self.type_map[qn] = td

    def resolve(self, type_ref: dict) -> dict:
        kind = type_ref.get("kind")
        name = type_ref.get("name")
        if kind == "qualifiedIdentifier":
            td = self.type_map.get(name)
            if td is None:
                return type_ref
            if td.get("kind") == "alias":
                return self._resolve_alias(td)
            return td
        return type_ref

    def _resolve_alias(self, alias_def: dict) -> dict:
        underlying = alias_def.get("underlyingType", {})
        if underlying.get("kind") == "qualifiedIdentifier":
            td = self.type_map.get(underlying.get("name"))
            if td and td.get("kind") == "alias":
                return self._resolve_alias(td)
            if td:
                return td
        result = dict(underlying)
        result["aliasName"] = alias_def.get("qualifiedName")
        return result


# ---------------------------------------------------------------------------
# XTCE Builder
# ---------------------------------------------------------------------------
class XtceBuilder:
    """Builds an XTCE XML tree from an F´ JSON dictionary."""

    def __init__(self, fp_dict: dict):
        self.fp_dict = fp_dict
        self.resolver = TypeResolver(fp_dict.get("typeDefinitions", []))
        self.metadata = fp_dict.get("metadata", {})

        # Dedup tracking
        self._param_types_created: set[str] = set()
        self._arg_types_created: set[str] = set()
        self._params_created: set[str] = set()

        # XML parent elements – populated during build
        self.param_type_set: Element = None  # type: ignore[assignment]
        self.param_set: Element = None  # type: ignore[assignment]
        self.container_set: Element = None  # type: ignore[assignment]
        self.arg_type_set: Element = None  # type: ignore[assignment]
        self.meta_cmd_set: Element = None  # type: ignore[assignment]

    # ===================================================================
    # Public entry point
    # ===================================================================
    def build(self) -> Element:
        deployment = self.metadata.get("deploymentName", "FprimeDeployment")
        root = Element(
            "SpaceSystem",
            attrib={
                "name": safe_name(deployment),
                "xmlns": XTCE_NS,
                "xmlns:xsi": XSI_NS,
                "xsi:schemaLocation": SCHEMA_LOC,
            },
        )
        self._build_telemetry(root)
        self._build_commands(root)
        return root

    # ===================================================================
    # Telemetry Metadata
    # ===================================================================
    def _build_telemetry(self, root: Element):
        tm = SubElement(root, "TelemetryMetaData")
        self.param_type_set = SubElement(tm, "ParameterTypeSet")
        self.param_set = SubElement(tm, "ParameterSet")
        self.container_set = SubElement(tm, "ContainerSet")

        # 1. Hardcoded base types + parameters + containers
        self._emit_base_param_types()
        self._emit_base_parameters()
        self._emit_base_containers()

        # 2. Auto-generated deployment-specific telemetry
        self._emit_telemetry_packets()

        # 3. Auto-generated deployment-specific events
        self._emit_events()

    # ------------------------------------------------------------------
    # Base (hardcoded) telemetry structures
    # ------------------------------------------------------------------
    def _emit_base_param_types(self):
        pts = self.param_type_set

        # --- CCSDS Space Packet Header types ---
        # Packet ID (aggregate: Version + Type + SecHdrFlag + APID)
        agg = SubElement(pts, "AggregateParameterType", name="CCSDS_Packet_ID_Type")
        ml = SubElement(agg, "MemberList")
        SubElement(ml, "Member", name="Version", typeRef="CCSDS_Version_Type")
        SubElement(ml, "Member", name="Type", typeRef="CCSDS_Type_Type")
        SubElement(ml, "Member", name="SecHdrFlag", typeRef="CCSDS_Sec_Hdr_Flag_Type")
        SubElement(ml, "Member", name="APID", typeRef="CCSDS_APID_Type")

        self._add_int_param_type(pts, "CCSDS_Version_Type", 3, signed=False)

        bt = SubElement(
            pts,
            "BooleanParameterType",
            name="CCSDS_Type_Type",
            zeroStringValue="TM",
            oneStringValue="TC",
        )
        SubElement(bt, "UnitSet")
        SubElement(bt, "IntegerDataEncoding", sizeInBits="1")

        bt2 = SubElement(
            pts,
            "BooleanParameterType",
            name="CCSDS_Sec_Hdr_Flag_Type",
            zeroStringValue="NotPresent",
            oneStringValue="Present",
        )
        SubElement(bt2, "UnitSet")
        SubElement(bt2, "IntegerDataEncoding", sizeInBits="1")

        self._add_int_param_type(pts, "CCSDS_APID_Type", 11, signed=False)

        # Packet Sequence (aggregate: GroupFlags + Count)
        agg2 = SubElement(
            pts, "AggregateParameterType", name="CCSDS_Packet_Sequence_Type"
        )
        ml2 = SubElement(agg2, "MemberList")
        SubElement(ml2, "Member", name="GroupFlags", typeRef="CCSDS_Group_Flags_Type")
        SubElement(
            ml2, "Member", name="Count", typeRef="CCSDS_Source_Sequence_Count_Type"
        )

        enum_gf = SubElement(
            pts, "EnumeratedParameterType", name="CCSDS_Group_Flags_Type"
        )
        SubElement(enum_gf, "UnitSet")
        SubElement(enum_gf, "IntegerDataEncoding", sizeInBits="2")
        el = SubElement(enum_gf, "EnumerationList")
        SubElement(el, "Enumeration", value="0", label="Continuation")
        SubElement(el, "Enumeration", value="1", label="First")
        SubElement(el, "Enumeration", value="2", label="Last")
        SubElement(el, "Enumeration", value="3", label="Standalone")

        self._add_int_param_type(
            pts, "CCSDS_Source_Sequence_Count_Type", 14, signed=False
        )

        pkt_len = SubElement(
            pts,
            "IntegerParameterType",
            name="CCSDS_Packet_Length_Type",
            signed="false",
            initialValue="0",
        )
        us = SubElement(pkt_len, "UnitSet")
        SubElement(us, "Unit", description="Size").text = "Octets"
        SubElement(pkt_len, "IntegerDataEncoding", sizeInBits="16")

        # --- F´ header types ---
        self._ensure_int_param_type("U8", 8, False)
        self._ensure_int_param_type("U16", 16, False)
        self._ensure_int_param_type("U32", 32, False)

        # FpTime aggregate: TimeBase(U16) + TimeContext(U8) + Seconds(U32) + Micros(U32)
        agg3 = SubElement(pts, "AggregateParameterType", name="FpTimeType")
        ml3 = SubElement(agg3, "MemberList")
        SubElement(ml3, "Member", name="TimeBase", typeRef="U16")
        SubElement(ml3, "Member", name="TimeContext", typeRef="U8")
        SubElement(ml3, "Member", name="Seconds", typeRef="U32")
        SubElement(ml3, "Member", name="Microseconds", typeRef="U32")

        # Register all base types
        self._param_types_created.update(
            [
                "CCSDS_Packet_ID_Type",
                "CCSDS_Version_Type",
                "CCSDS_Type_Type",
                "CCSDS_Sec_Hdr_Flag_Type",
                "CCSDS_APID_Type",
                "CCSDS_Packet_Sequence_Type",
                "CCSDS_Group_Flags_Type",
                "CCSDS_Source_Sequence_Count_Type",
                "CCSDS_Packet_Length_Type",
                "FpTimeType",
                "U8",
                "U16",
                "U32",
            ]
        )

    def _emit_base_parameters(self):
        ps = self.param_set
        self._add_param(ps, "CCSDS_Packet_ID", "CCSDS_Packet_ID_Type")
        self._add_param(ps, "CCSDS_Packet_Sequence", "CCSDS_Packet_Sequence_Type")
        self._add_param(ps, "CCSDS_Packet_Length", "CCSDS_Packet_Length_Type")
        self._add_param(ps, "DataDescType", "U16")
        self._add_param(ps, "FwTlmPacketizeIdType", "U16")
        self._add_param(ps, "FpTime", "FpTimeType")
        self._add_param(ps, "FwEventIdType", "U32")

    def _emit_base_containers(self):
        cs = self.container_set

        # 1. Abstract CCSDSPacket
        ccsds = SubElement(cs, "SequenceContainer", abstract="true", name="CCSDSPacket")
        el = SubElement(ccsds, "EntryList")
        SubElement(el, "ParameterRefEntry", parameterRef="CCSDS_Packet_ID")
        SubElement(el, "ParameterRefEntry", parameterRef="CCSDS_Packet_Sequence")
        SubElement(el, "ParameterRefEntry", parameterRef="CCSDS_Packet_Length")

        # 2. Abstract FpTlmPacket (packetized telemetry, APID=4)
        fp_tlm = SubElement(
            cs, "SequenceContainer", abstract="true", name="FpTlmPacket"
        )
        el2 = SubElement(fp_tlm, "EntryList")
        SubElement(el2, "ParameterRefEntry", parameterRef="DataDescType")
        SubElement(el2, "ParameterRefEntry", parameterRef="FwTlmPacketizeIdType")
        SubElement(el2, "ParameterRefEntry", parameterRef="FpTime")
        bc = SubElement(fp_tlm, "BaseContainer", containerRef="CCSDSPacket")
        rc = SubElement(bc, "RestrictionCriteria")
        cl = SubElement(rc, "ComparisonList")
        SubElement(cl, "Comparison", value="0", parameterRef="CCSDS_Packet_ID/Version")
        SubElement(
            cl,
            "Comparison",
            value=str(APID_PACKETIZED_TLM),
            parameterRef="CCSDS_Packet_ID/APID",
        )

        # 3. Abstract FpEventPacket (APID=2)
        fp_evt = SubElement(
            cs, "SequenceContainer", abstract="true", name="FpEventPacket"
        )
        el3 = SubElement(fp_evt, "EntryList")
        SubElement(el3, "ParameterRefEntry", parameterRef="DataDescType")
        SubElement(el3, "ParameterRefEntry", parameterRef="FwEventIdType")
        SubElement(el3, "ParameterRefEntry", parameterRef="FpTime")
        bc2 = SubElement(fp_evt, "BaseContainer", containerRef="CCSDSPacket")
        rc2 = SubElement(bc2, "RestrictionCriteria")
        cl2 = SubElement(rc2, "ComparisonList")
        SubElement(cl2, "Comparison", value="0", parameterRef="CCSDS_Packet_ID/Version")
        SubElement(
            cl2, "Comparison", value=str(APID_LOG), parameterRef="CCSDS_Packet_ID/APID"
        )

    # ------------------------------------------------------------------
    # Auto-generated telemetry packets
    # ------------------------------------------------------------------
    def _emit_telemetry_packets(self):
        """Generate concrete SequenceContainers for each telemetry packet."""
        cs = self.container_set
        channel_map = self._build_channel_map()

        for pkt_set in self.fp_dict.get("telemetryPacketSets", []):
            for pkt in pkt_set.get("members", []):
                pkt_name = pkt["name"]
                pkt_id = pkt["id"]
                channel_names: list[str] = pkt.get("members", [])

                # Ensure types + parameters exist for each channel
                for ch_name in channel_names:
                    ch = channel_map.get(ch_name)
                    if ch is None:
                        continue
                    xtce_type = self._get_xtce_param_type_name(ch["type"])
                    p_name = self._channel_param_name(ch_name)
                    self._ensure_param(p_name, xtce_type)

                # Concrete SequenceContainer
                sc = SubElement(cs, "SequenceContainer", name=f"{pkt_name}Packet")
                el = SubElement(sc, "EntryList")
                for ch_name in channel_names:
                    p_name = self._channel_param_name(ch_name)
                    SubElement(el, "ParameterRefEntry", parameterRef=p_name)
                bc = SubElement(sc, "BaseContainer", containerRef="FpTlmPacket")
                rc = SubElement(bc, "RestrictionCriteria")
                cl = SubElement(rc, "ComparisonList")
                SubElement(
                    cl,
                    "Comparison",
                    value=str(pkt_id),
                    parameterRef="FwTlmPacketizeIdType",
                )

    # ------------------------------------------------------------------
    # Auto-generated events
    # ------------------------------------------------------------------
    def _emit_events(self):
        """Generate a concrete SequenceContainer for each F´ event."""
        cs = self.container_set

        for evt in self.fp_dict.get("events", []):
            evt_qname: str = evt["name"]
            evt_xtce_name = safe_name(evt_qname)
            evt_id: int = evt["id"]
            formal_params: list[dict] = evt.get("formalParams", [])

            # Ensure types + parameters for each argument
            param_names: list[str] = []
            for fp in formal_params:
                xtce_type = self._get_xtce_param_type_name(fp["type"])
                p_name = f"{evt_xtce_name}_{fp['name']}"
                self._ensure_param(p_name, xtce_type)
                param_names.append(p_name)

            # SequenceContainer
            sc = SubElement(cs, "SequenceContainer", name=evt_xtce_name)
            el = SubElement(sc, "EntryList")
            for p_name in param_names:
                SubElement(el, "ParameterRefEntry", parameterRef=p_name)
            bc = SubElement(sc, "BaseContainer", containerRef="FpEventPacket")
            rc = SubElement(bc, "RestrictionCriteria")
            cl = SubElement(rc, "ComparisonList")
            SubElement(
                cl, "Comparison", value=hex_opcode(evt_id), parameterRef="FwEventIdType"
            )

    # ===================================================================
    # Command Metadata
    # ===================================================================
    def _build_commands(self, root: Element):
        cm = SubElement(root, "CommandMetaData")
        self.arg_type_set = SubElement(cm, "ArgumentTypeSet")
        self.meta_cmd_set = SubElement(cm, "MetaCommandSet")

        self._emit_base_arg_types()
        self._emit_base_commands()
        self._emit_concrete_commands()

    # ------------------------------------------------------------------
    # Base (hardcoded) command structures
    # ------------------------------------------------------------------
    def _emit_base_arg_types(self):
        ats = self.arg_type_set

        self._add_int_arg_type(ats, "CCSDS_Version_Type", 3, signed=False)

        bt = SubElement(
            ats,
            "BooleanArgumentType",
            name="CCSDS_Type_Type",
            zeroStringValue="TM",
            oneStringValue="TC",
        )
        SubElement(bt, "UnitSet")
        SubElement(bt, "IntegerDataEncoding", sizeInBits="1")

        bt2 = SubElement(
            ats,
            "BooleanArgumentType",
            name="CCSDS_Sec_Hdr_Flag_Type",
            zeroStringValue="NotPresent",
            oneStringValue="Present",
        )
        SubElement(bt2, "UnitSet")
        SubElement(bt2, "IntegerDataEncoding", sizeInBits="1")

        self._add_int_arg_type(ats, "CCSDS_APID_Type", 11, signed=False)

        self._add_int_arg_type(ats, "U32", 32, signed=False)

        enum_gf = SubElement(
            ats, "EnumeratedArgumentType", name="CCSDS_Group_Flags_Type"
        )
        SubElement(enum_gf, "UnitSet")
        SubElement(enum_gf, "IntegerDataEncoding", sizeInBits="2")
        el = SubElement(enum_gf, "EnumerationList")
        SubElement(el, "Enumeration", value="0", label="Continuation")
        SubElement(el, "Enumeration", value="1", label="First")
        SubElement(el, "Enumeration", value="2", label="Last")
        SubElement(el, "Enumeration", value="3", label="Standalone")

        self._arg_types_created.update(
            [
                "CCSDS_Version_Type",
                "CCSDS_Type_Type",
                "CCSDS_Sec_Hdr_Flag_Type",
                "CCSDS_APID_Type",
                "CCSDS_Group_Flags_Type",
                "U32",
            ]
        )

    def _emit_base_commands(self):
        mcs = self.meta_cmd_set

        # --- Abstract CCSDSPacket MetaCommand ---
        ccsds_cmd = SubElement(mcs, "MetaCommand", name="CCSDSPacket", abstract="true")
        arg_list = SubElement(ccsds_cmd, "ArgumentList")
        SubElement(
            arg_list,
            "Argument",
            argumentTypeRef="CCSDS_Version_Type",
            name="CCSDS_Version",
        )
        SubElement(
            arg_list, "Argument", argumentTypeRef="CCSDS_Type_Type", name="CCSDS_Type"
        )
        SubElement(
            arg_list,
            "Argument",
            argumentTypeRef="CCSDS_Sec_Hdr_Flag_Type",
            name="CCSDS_Sec_Hdr_Flag",
        )
        SubElement(
            arg_list, "Argument", argumentTypeRef="CCSDS_APID_Type", name="CCSDS_APID"
        )
        SubElement(
            arg_list,
            "Argument",
            argumentTypeRef="CCSDS_Group_Flags_Type",
            name="CCSDS_Group_Flags",
        )

        cc = SubElement(ccsds_cmd, "CommandContainer", name="CCSDSPacket")
        el = SubElement(cc, "EntryList")
        SubElement(el, "ArgumentRefEntry", argumentRef="CCSDS_Version")
        SubElement(el, "ArgumentRefEntry", argumentRef="CCSDS_Type")
        SubElement(el, "ArgumentRefEntry", argumentRef="CCSDS_Sec_Hdr_Flag")
        SubElement(el, "ArgumentRefEntry", argumentRef="CCSDS_APID")
        SubElement(el, "ArgumentRefEntry", argumentRef="CCSDS_Group_Flags")
        SubElement(
            el,
            "FixedValueEntry",
            name="CCSDS_Source_Sequence_Count",
            binaryValue="0000",
            sizeInBits="14",
        )
        SubElement(
            el,
            "FixedValueEntry",
            name="CCSDS_Packet_Length",
            binaryValue="0000",
            sizeInBits="16",
        )

        # --- Abstract FprimeCommand MetaCommand ---
        fp_cmd = SubElement(mcs, "MetaCommand", name="FprimeCommand", abstract="true")
        bmc = SubElement(fp_cmd, "BaseMetaCommand", metaCommandRef="CCSDSPacket")
        aal = SubElement(bmc, "ArgumentAssignmentList")
        SubElement(
            aal, "ArgumentAssignment", argumentName="CCSDS_Version", argumentValue="0"
        )
        SubElement(
            aal, "ArgumentAssignment", argumentName="CCSDS_Type", argumentValue="TC"
        )
        SubElement(
            aal,
            "ArgumentAssignment",
            argumentName="CCSDS_Sec_Hdr_Flag",
            argumentValue="NotPresent",
        )
        SubElement(
            aal,
            "ArgumentAssignment",
            argumentName="CCSDS_APID",
            argumentValue=str(APID_COMMAND),
        )
        SubElement(
            aal,
            "ArgumentAssignment",
            argumentName="CCSDS_Group_Flags",
            argumentValue="Standalone",
        )

        arg_list2 = SubElement(fp_cmd, "ArgumentList")
        SubElement(arg_list2, "Argument", argumentTypeRef="U32", name="Opcode")

        fc = SubElement(fp_cmd, "CommandContainer", name="FprimeCommand")
        el2 = SubElement(fc, "EntryList")
        SubElement(
            el2,
            "FixedValueEntry",
            name="Fprime_FW_PACKET_COMMAND",
            binaryValue="0000",
            sizeInBits="16",
        )
        SubElement(el2, "ArgumentRefEntry", argumentRef="Opcode")
        SubElement(fc, "BaseContainer", containerRef="CCSDSPacket")

    # ------------------------------------------------------------------
    # Auto-generated concrete commands
    # ------------------------------------------------------------------
    def _emit_concrete_commands(self):
        """Generate a concrete MetaCommand for each F´ command."""
        mcs = self.meta_cmd_set

        for cmd in self.fp_dict.get("commands", []):
            cmd_qname: str = cmd["name"]
            opcode: int = cmd["opcode"]
            formal_params: list[dict] = cmd.get("formalParams", [])

            mc = SubElement(mcs, "MetaCommand", name=safe_name(cmd_qname))
            if cmd.get("annotation"):
                ld = SubElement(mc, "LongDescription")
                ld.text = cmd["annotation"]

            # Inherit from FprimeCommand, assign opcode
            bmc = SubElement(mc, "BaseMetaCommand", metaCommandRef="FprimeCommand")
            aal = SubElement(bmc, "ArgumentAssignmentList")
            SubElement(
                aal,
                "ArgumentAssignment",
                argumentName="Opcode",
                argumentValue=hex_opcode(opcode),
            )

            # Arguments
            if formal_params:
                arg_list = SubElement(mc, "ArgumentList")
                for fp in formal_params:
                    arg_type_name = self._get_xtce_arg_type_name(fp["type"])
                    SubElement(
                        arg_list,
                        "Argument",
                        argumentTypeRef=arg_type_name,
                        name=fp["name"],
                    )

            # CommandContainer
            cc = SubElement(mc, "CommandContainer", name=safe_name(cmd_qname))
            el = SubElement(cc, "EntryList")
            for fp in formal_params:
                SubElement(el, "ArgumentRefEntry", argumentRef=fp["name"])
            SubElement(cc, "BaseContainer", containerRef="FprimeCommand")

    # ===================================================================
    # Type creation helpers – Parameter Types (telemetry side)
    # ===================================================================
    def _get_xtce_param_type_name(self, type_ref: dict) -> str:
        """Return the XTCE parameter type name, creating it if necessary."""
        resolved = self.resolver.resolve(type_ref)
        kind = resolved.get("kind")

        if kind == "integer":
            size = resolved.get("size", 32)
            signed = resolved.get("signed", False)
            name = f"{'I' if signed else 'U'}{size}"
            self._ensure_int_param_type(name, size, signed)
            return name

        if kind == "float":
            size = resolved.get("size", 32)
            name = f"F{size}"
            self._ensure_float_param_type(name, size)
            return name

        if kind == "bool":
            name = "FpBool"
            self._ensure_bool_param_type(name)
            return name

        if kind == "string":
            max_len = resolved.get("size", 80)
            name = f"FpString_{max_len}"
            self._ensure_string_param_type(name, max_len)
            return name

        if kind == "enum":
            qn = resolved.get("qualifiedName", "UnknownEnum")
            name = safe_name(qn)
            self._ensure_enum_param_type(name, resolved)
            return name

        if kind == "struct":
            qn = resolved.get("qualifiedName", "UnknownStruct")
            name = safe_name(qn)
            self._ensure_struct_param_type(name, resolved)
            return name

        if kind == "array":
            qn = resolved.get("qualifiedName", "UnknownArray")
            name = safe_name(qn)
            self._ensure_array_param_type(name, resolved)
            return name

        if kind == "alias":
            return self._get_xtce_param_type_name(
                resolved.get("underlyingType", resolved)
            )

        # Fallback
        self._ensure_int_param_type("U32", 32, False)
        return "U32"

    def _ensure_int_param_type(self, name: str, size: int, signed: bool):
        if name not in self._param_types_created:
            self._add_int_param_type(self.param_type_set, name, size, signed)
            self._param_types_created.add(name)

    def _ensure_float_param_type(self, name: str, size: int):
        if name not in self._param_types_created:
            ft = SubElement(self.param_type_set, "FloatParameterType", name=name)
            SubElement(ft, "UnitSet")
            SubElement(ft, "FloatDataEncoding", sizeInBits=str(size))
            self._param_types_created.add(name)

    def _ensure_bool_param_type(self, name: str):
        if name not in self._param_types_created:
            bt = SubElement(self.param_type_set, "BooleanParameterType", name=name)
            SubElement(bt, "UnitSet")
            SubElement(bt, "IntegerDataEncoding", sizeInBits="8")
            self._param_types_created.add(name)

    def _ensure_string_param_type(self, name: str, max_len: int):
        if name not in self._param_types_created:
            st = SubElement(self.param_type_set, "StringParameterType", name=name)
            SubElement(st, "UnitSet")
            se = SubElement(st, "StringDataEncoding", encoding="UTF-8")
            sso = SubElement(se, "SizeInBits")
            fixed = SubElement(sso, "Fixed")
            SubElement(fixed, "FixedValue").text = str((2 + max_len) * 8)
            SubElement(sso, "LeadingSize", sizeInBitsOfSizeTag="16")
            self._param_types_created.add(name)

    def _ensure_enum_param_type(self, name: str, enum_def: dict):
        if name not in self._param_types_created:
            self._param_types_created.add(name)
            rep_size = enum_def.get("representationType", {}).get("size", 8)
            et = SubElement(self.param_type_set, "EnumeratedParameterType", name=name)
            SubElement(et, "UnitSet")
            SubElement(et, "IntegerDataEncoding", sizeInBits=str(rep_size))
            el = SubElement(et, "EnumerationList")
            for ec in enum_def.get("enumeratedConstants", []):
                SubElement(el, "Enumeration", value=str(ec["value"]), label=ec["name"])

    def _ensure_struct_param_type(self, name: str, struct_def: dict):
        if name not in self._param_types_created:
            self._param_types_created.add(name)
            agg = SubElement(self.param_type_set, "AggregateParameterType", name=name)
            ml = SubElement(agg, "MemberList")
            members = struct_def.get("members", {})
            for m_name, m_info in sorted(
                members.items(), key=lambda x: x[1].get("index", 0)
            ):
                m_type = self._get_xtce_param_type_name(m_info["type"])
                SubElement(ml, "Member", name=m_name, typeRef=m_type)

    def _ensure_array_param_type(self, name: str, array_def: dict):
        if name not in self._param_types_created:
            self._param_types_created.add(name)
            arr_size = array_def.get("size", 0)
            elem_type = self._get_xtce_param_type_name(array_def.get("elementType", {}))
            at = SubElement(
                self.param_type_set,
                "ArrayParameterType",
                name=name,
                arrayTypeRef=elem_type,
            )
            SubElement(at, "DimensionList").append(
                self._make_dimension(0, arr_size - 1)
            )

    # ===================================================================
    # Type creation helpers – Argument Types (command side)
    # ===================================================================
    def _get_xtce_arg_type_name(self, type_ref: dict) -> str:
        """Return the XTCE argument type name, creating it if necessary."""
        resolved = self.resolver.resolve(type_ref)
        kind = resolved.get("kind")

        if kind == "integer":
            size = resolved.get("size", 32)
            signed = resolved.get("signed", False)
            name = f"Arg_{'I' if signed else 'U'}{size}"
            self._ensure_int_arg_type(name, size, signed)
            return name

        if kind == "float":
            size = resolved.get("size", 32)
            name = f"Arg_F{size}"
            self._ensure_float_arg_type(name, size)
            return name

        if kind == "bool":
            name = "Arg_FpBool"
            self._ensure_bool_arg_type(name)
            return name

        if kind == "string":
            max_len = resolved.get("size", 80)
            name = f"Arg_FpString_{max_len}"
            self._ensure_string_arg_type(name, max_len)
            return name

        if kind == "enum":
            qn = resolved.get("qualifiedName", "UnknownEnum")
            name = f"Arg_{safe_name(qn)}"
            self._ensure_enum_arg_type(name, resolved)
            return name

        if kind == "struct":
            qn = resolved.get("qualifiedName", "UnknownStruct")
            name = f"Arg_{safe_name(qn)}"
            self._ensure_struct_arg_type(name, resolved)
            return name

        if kind == "array":
            qn = resolved.get("qualifiedName", "UnknownArray")
            name = f"Arg_{safe_name(qn)}"
            self._ensure_array_arg_type(name, resolved)
            return name

        if kind == "alias":
            return self._get_xtce_arg_type_name(
                resolved.get("underlyingType", resolved)
            )

        self._ensure_int_arg_type("Arg_U32", 32, False)
        return "Arg_U32"

    def _ensure_int_arg_type(self, name: str, size: int, signed: bool):
        if name not in self._arg_types_created:
            self._add_int_arg_type(self.arg_type_set, name, size, signed)
            self._arg_types_created.add(name)

    def _ensure_float_arg_type(self, name: str, size: int):
        if name not in self._arg_types_created:
            ft = SubElement(self.arg_type_set, "FloatArgumentType", name=name)
            SubElement(ft, "UnitSet")
            SubElement(ft, "FloatDataEncoding", sizeInBits=str(size))
            self._arg_types_created.add(name)

    def _ensure_bool_arg_type(self, name: str):
        if name not in self._arg_types_created:
            bt = SubElement(self.arg_type_set, "BooleanArgumentType", name=name)
            SubElement(bt, "UnitSet")
            SubElement(bt, "IntegerDataEncoding", sizeInBits="8")
            self._arg_types_created.add(name)

    def _ensure_string_arg_type(self, name: str, max_len: int):
        if name not in self._arg_types_created:
            st = SubElement(self.arg_type_set, "StringArgumentType", name=name)
            SubElement(st, "UnitSet")
            se = SubElement(st, "StringDataEncoding", encoding="UTF-8")
            sso = SubElement(se, "SizeInBits")
            fixed = SubElement(sso, "Fixed")
            SubElement(fixed, "FixedValue").text = str((2 + max_len) * 8)
            SubElement(sso, "LeadingSize", sizeInBitsOfSizeTag="16")
            self._arg_types_created.add(name)

    def _ensure_enum_arg_type(self, name: str, enum_def: dict):
        if name not in self._arg_types_created:
            self._arg_types_created.add(name)
            rep_size = enum_def.get("representationType", {}).get("size", 8)
            et = SubElement(self.arg_type_set, "EnumeratedArgumentType", name=name)
            SubElement(et, "UnitSet")
            SubElement(et, "IntegerDataEncoding", sizeInBits=str(rep_size))
            el = SubElement(et, "EnumerationList")
            for ec in enum_def.get("enumeratedConstants", []):
                SubElement(el, "Enumeration", value=str(ec["value"]), label=ec["name"])

    def _ensure_struct_arg_type(self, name: str, struct_def: dict):
        if name not in self._arg_types_created:
            self._arg_types_created.add(name)
            agg = SubElement(self.arg_type_set, "AggregateArgumentType", name=name)
            ml = SubElement(agg, "MemberList")
            members = struct_def.get("members", {})
            for m_name, m_info in sorted(
                members.items(), key=lambda x: x[1].get("index", 0)
            ):
                m_type = self._get_xtce_arg_type_name(m_info["type"])
                SubElement(ml, "Member", name=m_name, typeRef=m_type)

    def _ensure_array_arg_type(self, name: str, array_def: dict):
        if name not in self._arg_types_created:
            self._arg_types_created.add(name)
            arr_size = array_def.get("size", 0)
            elem_type = self._get_xtce_arg_type_name(array_def.get("elementType", {}))
            at = SubElement(
                self.arg_type_set,
                "ArrayArgumentType",
                name=name,
                arrayTypeRef=elem_type,
                numberOfDimensions="1",
            )
            SubElement(at, "DimensionList").append(
                self._make_dimension(0, arr_size - 1)
            )

    # ===================================================================
    # Utility methods
    # ===================================================================
    @staticmethod
    def _make_dimension(start: int, end: int) -> Element:
        dim = Element("Dimension")
        si = SubElement(dim, "StartingIndex")
        SubElement(si, "FixedValue").text = str(start)
        ei = SubElement(dim, "EndingIndex")
        SubElement(ei, "FixedValue").text = str(end)
        return dim

    def _build_channel_map(self) -> dict[str, dict]:
        return {ch["name"]: ch for ch in self.fp_dict.get("telemetryChannels", [])}

    @staticmethod
    def _channel_param_name(ch_qname: str) -> str:
        """Derive XTCE parameter name from a channel qualified name.

        Strips the top-level prefix, keeping componentInstance + channelName,
        then converts dots to '>'.  The instance name is capitalized to match
        the handcoded style (``DummyTlm>DummyCounter``).

        ``FpYamcs.dummyTlm.DummyCounter`` → ``DummyTlm>DummyCounter``
        """
        parts = ch_qname.rsplit(".", 2)
        if len(parts) >= 2:
            inst = parts[-2]
            inst = inst[0].upper() + inst[1:] if inst else inst
            return f"{inst}>{parts[-1]}"
        return safe_name(ch_qname)

    def _add_param(self, parent: Element, name: str, type_ref: str):
        if name not in self._params_created:
            SubElement(parent, "Parameter", name=name, parameterTypeRef=type_ref)
            self._params_created.add(name)

    def _ensure_param(self, name: str, type_ref: str):
        self._add_param(self.param_set, name, type_ref)

    @staticmethod
    def _add_int_param_type(parent: Element, name: str, size: int, signed: bool):
        ipt = SubElement(
            parent,
            "IntegerParameterType",
            name=name,
            signed="true" if signed else "false",
        )
        SubElement(ipt, "UnitSet")
        enc: dict[str, str] = {"sizeInBits": str(size)}
        if size in (8, 16, 32, 64):
            enc["encoding"] = "twosComplement" if signed else "unsigned"
        SubElement(ipt, "IntegerDataEncoding", **enc)

    @staticmethod
    def _add_int_arg_type(parent: Element, name: str, size: int, signed: bool):
        iat = SubElement(
            parent,
            "IntegerArgumentType",
            name=name,
            signed="true" if signed else "false",
        )
        SubElement(iat, "UnitSet")
        enc: dict[str, str] = {"sizeInBits": str(size)}
        if size in (8, 16, 32, 64):
            enc["encoding"] = "twosComplement" if signed else "unsigned"
        SubElement(iat, "IntegerDataEncoding", **enc)


# ---------------------------------------------------------------------------
# Pretty-print XML
# ---------------------------------------------------------------------------
def pretty_xml(root: Element) -> str:
    rough = tostring(root, encoding="unicode")
    dom = parseString(rough)
    pretty = dom.toprettyxml(indent="\t", encoding=None)
    lines = pretty.split("\n")
    lines[0] = '<?xml version="1.0" encoding="UTF-8"?>'
    return "\n".join(line for line in lines if line.strip())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Convert an F´ JSON dictionary to XTCE for YAMCS"
    )
    parser.add_argument("input", help="Path to F´ JSON dictionary file")
    parser.add_argument(
        "output", nargs="?", default=None, help="Output XTCE XML file (default: stdout)"
    )
    args = parser.parse_args()

    with open(args.input, "r") as f:
        fp_dict = json.load(f)

    builder = XtceBuilder(fp_dict)
    root = builder.build()
    xml_str = pretty_xml(root)

    if args.output:
        with open(args.output, "w") as f:
            f.write(xml_str)
            f.write("\n")
        print(f"Wrote XTCE to {args.output}", file=sys.stderr)
    else:
        print(xml_str)


if __name__ == "__main__":
    main()
