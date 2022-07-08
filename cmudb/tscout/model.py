"""
model.py

Convert C types to BPF types.
Define the Operating Units (OUs) and metrics to be collected.
"""

import logging
import struct
import sys
from dataclasses import dataclass
from enum import Enum, unique
from typing import List, Mapping, Tuple

import clang.cindex

logger = logging.getLogger("tscout")

FLOAT_DOUBLE_NDIGITS = 3


@unique
class BPFType(str, Enum):
    """BPF only has signed and unsigned integers."""

    I8 = "s8"
    I16 = "s16"
    I32 = "s32"
    I64 = "s64"
    U8 = "u8"
    U16 = "u16"
    U32 = "u32"
    U64 = "u64"
    POINTER = "void *"


@dataclass
class BPFVariable:
    # TODO(Matt): Should this extend Field? Their members look very similar now. However, model doesn't know about clang_parser
    #  and maybe it should stay that way.
    name: str
    c_type: clang.cindex.TypeKind
    pg_type: str = None  # Some BPFVariables don't originate from Postgres (e.g., metrics and metadata) so default None
    alignment: int = None  # Non-None for the first field of a struct, using alignment value of the struct.

    def alignment_string(self):
        return f" __attribute__ ((aligned ({self.alignment})))" if self.alignment is not None else ""

    def serialize(self, output_event):
        """
        Serialize this variable given the output event containing its value.

        Parameters
        ----------
        output_event
            The perf output event that contains the output value for this var.

        Returns
        -------
        val : str
            The serialized value of this variable.
        """
        if self.c_type == clang.cindex.TypeKind.FLOAT:
            float_val = struct.unpack("f", getattr(output_event, self.name).to_bytes(4, byteorder=sys.byteorder))[0]
            float_val = round(float_val, FLOAT_DOUBLE_NDIGITS)
            return str(float_val)
        if self.c_type == clang.cindex.TypeKind.DOUBLE:
            double_val = struct.unpack("d", getattr(output_event, self.name).to_bytes(8, byteorder=sys.byteorder))[0]
            double_val = round(double_val, FLOAT_DOUBLE_NDIGITS)
            return str(double_val)

        return str(getattr(output_event, self.name))


# Map from Clang type kinds to BPF types.
CLANG_TO_BPF = {
    clang.cindex.TypeKind.BOOL: BPFType.U8,
    clang.cindex.TypeKind.CHAR_U: BPFType.U8,
    clang.cindex.TypeKind.UCHAR: BPFType.U8,
    clang.cindex.TypeKind.USHORT: BPFType.U16,
    clang.cindex.TypeKind.UINT: BPFType.U32,
    clang.cindex.TypeKind.ULONG: BPFType.U64,
    clang.cindex.TypeKind.ULONGLONG: BPFType.U64,
    clang.cindex.TypeKind.CHAR_S: BPFType.I8,
    clang.cindex.TypeKind.SCHAR: BPFType.I8,
    clang.cindex.TypeKind.SHORT: BPFType.I16,
    clang.cindex.TypeKind.INT: BPFType.I32,
    clang.cindex.TypeKind.LONG: BPFType.I64,
    clang.cindex.TypeKind.LONGLONG: BPFType.I64,
    # We memcpy floats and doubles into unsigned integer types of the same size because BPF doesn't support floating
    # point types. We later read this memory back as the original floating point type in user-space.
    clang.cindex.TypeKind.FLOAT: BPFType.U32,
    clang.cindex.TypeKind.DOUBLE: BPFType.U64,
    clang.cindex.TypeKind.ENUM: BPFType.I32,
    clang.cindex.TypeKind.POINTER: BPFType.POINTER,
    clang.cindex.TypeKind.FUNCTIONPROTO: BPFType.POINTER,
    clang.cindex.TypeKind.INCOMPLETEARRAY: BPFType.POINTER,
    clang.cindex.TypeKind.CONSTANTARRAY: BPFType.POINTER,
}


# The following mass definitions look messy after auto-formatting.
# fmt: off

"""
An OU is specified via postgres_function.

postgres_function : str
    The name of the PostgreSQL function generating the features marker.
"""
OU_DEFS = [
    "ExecAgg",
    "ExecAppend",
    "ExecBitmapAnd",
    "ExecBitmapHeapScan",
    "ExecBitmapIndexScan",
    "ExecBitmapOr",
    "ExecCteScan",
    "ExecCustomScan",
    "ExecForeignScan",
    "ExecFunctionScan",
    "ExecGather",
    "ExecGatherMerge",
    "ExecGroup",
    "ExecHash",
    "ExecHashJoinImpl",
    "ExecIncrementalSort",
    "ExecIndexOnlyScan",
    "ExecIndexScan",
    "ExecLimit",
    "ExecLockRows",
    "ExecMaterial",
    "ExecMemoize",
    "ExecMergeAppend",
    "ExecMergeJoin",

    "ExecModifyTableInsert",
    "ExecModifyTableUpdate",
    "ExecModifyTableDelete",
    "ExecModifyTableIndexInsert",
    "ExecAfterQueryTrigger",

    "ExecNamedTuplestoreScan",
    "ExecNestLoop",
    "ExecProjectSet",
    "ExecRecursiveUnion",
    "ExecResult",
    "ExecSampleScan",
    "ExecSeqScan",
    "ExecSetOp",
    "ExecSort",
    "ExecSubPlan",
    "ExecSubqueryScan",
    "ExecTableFuncScan",
    "ExecTidRangeScan",
    "ExecTidScan",
    "ExecUnique",
    "ExecValuesScan",
    "ExecWindowAgg",
    "ExecWorkTableScan",

    "ExecDestReceiverRemote",
]

# The metrics to be defined for every OU. If you add anything to these metrics, consider if it should be accumulated
# across invocations and adjust code related to SUBST_ACCUMULATE as needed.
OU_METRICS = (
    BPFVariable(name="start_time",
                c_type=clang.cindex.TypeKind.ULONG,
                alignment=8),
    BPFVariable(name="end_time",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="cpu_cycles",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="instructions",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="cache_references",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="cache_misses",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="ref_cpu_cycles",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="network_bytes_read",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="network_bytes_written",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="disk_bytes_read",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="disk_bytes_written",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="memory_bytes",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="elapsed_us",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="invocation_count",
                c_type=clang.cindex.TypeKind.UINT),
    BPFVariable(name="pid",
                c_type=clang.cindex.TypeKind.UINT),
    BPFVariable(name="cpu_id",
                c_type=clang.cindex.TypeKind.UCHAR),
)


# fmt: on
@dataclass
class OperatingUnit:
    """
    An operating unit is the NoisePage representation of a PostgreSQL operator.

    Parameters
    ----------
    function : str
        The name of the PostgreSQL function emitting the features.
    """

    function: str

    def name(self) -> str:
        return self.function

    def begin_marker(self) -> str:
        return self.name() + "_begin"

    def end_marker(self) -> str:
        return self.name() + "_end"

    def features_markers(self) -> str:
        return [self.name() + "_features", self.name() + "_features_payload"]

    def flush_marker(self) -> str:
        return self.name() + "_flush"


class Model:
    def __init__(self):
        operating_units = []

        for postgres_function in OU_DEFS:
            new_ou = OperatingUnit(postgres_function)
            operating_units.append(new_ou)

        self.operating_units = operating_units
        self.metrics = OU_METRICS
