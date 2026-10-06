#!/usr/bin/env python3
"""
wazuh_syncschema.py

Builds `Message{FullSession}` FlatBuffers for the Wazuh 5.x stateful sync
endpoint (POST /wazuh-manager/stateful).

Written directly against the published schema rather than generated with
`flatc`, so nothing outside the `flatbuffers` runtime is needed:

    src/shared_modules/utils/flatbuffers/schemas/inventorySync.fbs  (tag 5.0.0)

The schema's own comments describe the contract: a whole synchronisation
session travels as ONE Message{FullSession} request, the HTTP response IS the
session result, and re-applying the same session is idempotent — so a retry is
simply a re-POST of the same buffer. There are no acks and no sequence numbers.

Field slots below follow declaration order in the .fbs. A union field occupies
TWO slots: the type byte, then the offset. Getting either wrong produces a
buffer the manager rejects with a bare 400, so the self-test at the bottom
parses every buffer back before it is ever sent.

    python3 wazuh_syncschema.py --self-test
"""

from __future__ import annotations

import json
import sys

import flatbuffers

# --- enums (values are declaration order in the .fbs) ----------------------


class Mode:
    ModuleDelta = 0
    ModuleCheck = 1
    MetadataDelta = 2
    MetadataCheck = 3
    GroupDelta = 4
    GroupCheck = 5


class Operation:
    Upsert = 0
    Delete = 1


class Option:
    Sync = 0
    VDFirst = 1
    VDSync = 2


class SessionPayload:
    NONE = 0
    SyncData = 1
    Cleans = 2
    ChecksumModule = 3


class MessageType:
    NONE = 0
    DataValue = 1
    DataClean = 2
    ChecksumModule = 3
    Start = 4
    DataContext = 5
    FullSession = 6


# --- builders --------------------------------------------------------------
# FlatBuffers requires every string and vector to be created BEFORE the table
# that references it is started, which is why each helper takes prepared
# offsets rather than raw values.


def _str_vector(b: flatbuffers.Builder, values: list[str]) -> int:
    offsets = [b.CreateString(v) for v in values]
    b.StartVector(4, len(offsets), 4)
    for off in reversed(offsets):
        b.PrependUOffsetTRelative(off)
    return b.EndVector()


def _offset_vector(b: flatbuffers.Builder, offsets: list[int]) -> int:
    b.StartVector(4, len(offsets), 4)
    for off in reversed(offsets):
        b.PrependUOffsetTRelative(off)
    return b.EndVector()


def build_data_value(b: flatbuffers.Builder, *, operation: int, doc_id: str,
                     index: str, version: int, data: bytes) -> int:
    """table DataValue { operation; id; index; version; data:[byte]; }"""
    id_off = b.CreateString(doc_id)
    idx_off = b.CreateString(index)
    data_off = b.CreateByteVector(data)

    b.StartObject(5)
    b.PrependInt8Slot(0, operation, 0)
    b.PrependUOffsetTRelativeSlot(1, id_off, 0)
    b.PrependUOffsetTRelativeSlot(2, idx_off, 0)
    b.PrependUint64Slot(3, version, 0)
    b.PrependUOffsetTRelativeSlot(4, data_off, 0)
    return b.EndObject()


def build_data_context(b: flatbuffers.Builder, *, doc_id: str, index: str,
                       data: bytes) -> int:
    """table DataContext { id; index; data:[byte]; }"""
    id_off = b.CreateString(doc_id)
    idx_off = b.CreateString(index)
    data_off = b.CreateByteVector(data)

    b.StartObject(3)
    b.PrependUOffsetTRelativeSlot(0, id_off, 0)
    b.PrependUOffsetTRelativeSlot(1, idx_off, 0)
    b.PrependUOffsetTRelativeSlot(2, data_off, 0)
    return b.EndObject()


def build_start(b: flatbuffers.Builder, *, module: str, mode: int,
                indices: list[str], option: int, agent: dict,
                cluster_name: str = "wazuh", global_version: int = 0,
                feed_offset: int = 0) -> int:
    """table Start { module; mode; index:[string]; option; architecture;
    hostname; osname; osplatform; ostype; osversion; agentversion; agentname;
    agentid; groups:[string]; global_version; cluster_name; feed_offset; }"""
    host = agent.get("host", {})
    os_ = host.get("os", {})

    module_off = b.CreateString(module)
    idx_vec = _str_vector(b, indices)
    arch_off = b.CreateString(host.get("architecture", ""))
    hostname_off = b.CreateString(host.get("hostname", ""))
    osname_off = b.CreateString(os_.get("name", ""))
    osplat_off = b.CreateString(os_.get("platform", ""))
    ostype_off = b.CreateString(os_.get("type", ""))
    osver_off = b.CreateString(os_.get("version", ""))
    agentver_off = b.CreateString(agent.get("version", ""))
    agentname_off = b.CreateString(agent.get("name", ""))
    agentid_off = b.CreateString(agent.get("id", ""))
    groups_vec = _str_vector(b, agent.get("groups", []) or [])
    cluster_off = b.CreateString(cluster_name)

    b.StartObject(17)
    b.PrependUOffsetTRelativeSlot(0, module_off, 0)
    b.PrependInt8Slot(1, mode, 0)
    b.PrependUOffsetTRelativeSlot(2, idx_vec, 0)
    b.PrependInt8Slot(3, option, 0)
    b.PrependUOffsetTRelativeSlot(4, arch_off, 0)
    b.PrependUOffsetTRelativeSlot(5, hostname_off, 0)
    b.PrependUOffsetTRelativeSlot(6, osname_off, 0)
    b.PrependUOffsetTRelativeSlot(7, osplat_off, 0)
    b.PrependUOffsetTRelativeSlot(8, ostype_off, 0)
    b.PrependUOffsetTRelativeSlot(9, osver_off, 0)
    b.PrependUOffsetTRelativeSlot(10, agentver_off, 0)
    b.PrependUOffsetTRelativeSlot(11, agentname_off, 0)
    b.PrependUOffsetTRelativeSlot(12, agentid_off, 0)
    b.PrependUOffsetTRelativeSlot(13, groups_vec, 0)
    b.PrependUint64Slot(14, global_version, 0)
    b.PrependUOffsetTRelativeSlot(15, cluster_off, 0)
    b.PrependUint64Slot(16, feed_offset, 0)
    return b.EndObject()


def build_sync_data(b: flatbuffers.Builder, values: list[int],
                    contexts: list[int]) -> int:
    """table SyncData { values:[DataValue]; contexts:[DataContext]; }"""
    values_vec = _offset_vector(b, values) if values else None
    contexts_vec = _offset_vector(b, contexts) if contexts else None

    b.StartObject(2)
    if values_vec is not None:
        b.PrependUOffsetTRelativeSlot(0, values_vec, 0)
    if contexts_vec is not None:
        b.PrependUOffsetTRelativeSlot(1, contexts_vec, 0)
    return b.EndObject()


def build_full_session(b: flatbuffers.Builder, start_off: int,
                       payload_type: int, payload_off: int) -> int:
    """table FullSession { start; payload:SessionPayload; }

    The union takes two slots: 1 = payload_type, 2 = payload.
    """
    b.StartObject(3)
    b.PrependUOffsetTRelativeSlot(0, start_off, 0)
    b.PrependUint8Slot(1, payload_type, 0)
    b.PrependUOffsetTRelativeSlot(2, payload_off, 0)
    return b.EndObject()


def build_message(b: flatbuffers.Builder, content_type: int,
                  content_off: int) -> int:
    """table Message { content:MessageType; }  root_type Message"""
    b.StartObject(2)
    b.PrependUint8Slot(0, content_type, 0)
    b.PrependUOffsetTRelativeSlot(1, content_off, 0)
    return b.EndObject()


def build_session(*, module: str, indices: list[str], agent: dict,
                  documents: list[dict], mode: int = Mode.ModuleDelta,
                  option: int = Option.Sync, cluster_name: str = "wazuh",
                  contexts: list[dict] | None = None) -> bytes:
    """Assemble a complete Message{FullSession} buffer.

    `documents` are dicts of {id, index, version?, operation?, data} where data
    is either bytes or a JSON-serialisable object.
    """
    b = flatbuffers.Builder(4096)

    value_offsets = []
    for doc in documents:
        data = doc["data"]
        if not isinstance(data, (bytes, bytearray)):
            data = json.dumps(data, separators=(",", ":")).encode("utf-8")
        value_offsets.append(build_data_value(
            b,
            operation=doc.get("operation", Operation.Upsert),
            doc_id=doc["id"],
            index=doc["index"],
            version=doc.get("version", 1),
            data=bytes(data),
        ))

    context_offsets = []
    for ctx in (contexts or []):
        data = ctx["data"]
        if not isinstance(data, (bytes, bytearray)):
            data = json.dumps(data, separators=(",", ":")).encode("utf-8")
        context_offsets.append(build_data_context(
            b, doc_id=ctx["id"], index=ctx["index"], data=bytes(data)))

    payload_off = build_sync_data(b, value_offsets, context_offsets)
    start_off = build_start(b, module=module, mode=mode, indices=indices,
                            option=option, agent=agent,
                            cluster_name=cluster_name)
    session_off = build_full_session(b, start_off, SessionPayload.SyncData,
                                     payload_off)
    msg_off = build_message(b, MessageType.FullSession, session_off)
    b.Finish(msg_off)
    return bytes(b.Output())


# --- reading back ----------------------------------------------------------
# Used by the self-test. A buffer that cannot be parsed here will certainly be
# rejected by the manager, and this says why while the sender would not.


class _Table:
    def __init__(self, buf: bytes, pos: int):
        self.buf, self.pos = buf, pos
        self.vtable = pos - int.from_bytes(buf[pos:pos + 4], "little", signed=True)
        self.vtable_size = int.from_bytes(
            buf[self.vtable:self.vtable + 2], "little")

    def offset(self, slot: int) -> int:
        vo = 4 + slot * 2
        if vo >= self.vtable_size:
            return 0
        return int.from_bytes(self.buf[self.vtable + vo:self.vtable + vo + 2],
                              "little")

    def indirect(self, off: int) -> int:
        return off + int.from_bytes(self.buf[off:off + 4], "little")

    def table(self, slot: int):
        o = self.offset(slot)
        return _Table(self.buf, self.indirect(self.pos + o)) if o else None

    def string(self, slot: int) -> str | None:
        o = self.offset(slot)
        if not o:
            return None
        p = self.indirect(self.pos + o)
        n = int.from_bytes(self.buf[p:p + 4], "little")
        return self.buf[p + 4:p + 4 + n].decode("utf-8")

    def byte(self, slot: int, default: int = 0) -> int:
        o = self.offset(slot)
        return self.buf[self.pos + o] if o else default

    def uint64(self, slot: int, default: int = 0) -> int:
        o = self.offset(slot)
        if not o:
            return default
        return int.from_bytes(self.buf[self.pos + o:self.pos + o + 8], "little")

    def vector_len(self, slot: int) -> int:
        o = self.offset(slot)
        if not o:
            return 0
        p = self.indirect(self.pos + o)
        return int.from_bytes(self.buf[p:p + 4], "little")

    def vector_element(self, slot: int, i: int):
        p = self.indirect(self.pos + self.offset(slot)) + 4 + i * 4
        return _Table(self.buf, p + int.from_bytes(self.buf[p:p + 4], "little"))

    def byte_vector(self, slot: int) -> bytes:
        o = self.offset(slot)
        if not o:
            return b""
        p = self.indirect(self.pos + o)
        n = int.from_bytes(self.buf[p:p + 4], "little")
        return self.buf[p + 4:p + 4 + n]

    def string_vector(self, slot: int) -> list[str]:
        out = []
        for i in range(self.vector_len(slot)):
            p = self.indirect(self.pos + self.offset(slot)) + 4 + i * 4
            sp = p + int.from_bytes(self.buf[p:p + 4], "little")
            n = int.from_bytes(self.buf[sp:sp + 4], "little")
            out.append(self.buf[sp + 4:sp + 4 + n].decode("utf-8"))
        return out


def parse_session(buf: bytes) -> dict:
    """Read a Message{FullSession} back into a plain dict."""
    root = _Table(buf, int.from_bytes(buf[0:4], "little"))
    content_type = root.byte(0)
    if content_type != MessageType.FullSession:
        raise ValueError(f"root content type is {content_type}, "
                         f"expected FullSession ({MessageType.FullSession})")
    session = root.table(1)
    start = session.table(0)
    payload_type = session.byte(1)
    if payload_type != SessionPayload.SyncData:
        raise ValueError(f"payload type is {payload_type}, expected SyncData")
    payload = session.table(2)

    values = []
    for i in range(payload.vector_len(0)):
        dv = payload.vector_element(0, i)
        values.append({
            "operation": dv.byte(0),
            "id": dv.string(1),
            "index": dv.string(2),
            "version": dv.uint64(3),
            "data": dv.byte_vector(4),
        })

    return {
        "start": {
            "module": start.string(0),
            "mode": start.byte(1),
            "index": start.string_vector(2),
            "option": start.byte(3),
            "architecture": start.string(4),
            "hostname": start.string(5),
            "osname": start.string(6),
            "osplatform": start.string(7),
            "ostype": start.string(8),
            "osversion": start.string(9),
            "agentversion": start.string(10),
            "agentname": start.string(11),
            "agentid": start.string(12),
            "groups": start.string_vector(13),
            "global_version": start.uint64(14),
            "cluster_name": start.string(15),
            "feed_offset": start.uint64(16),
        },
        "values": values,
    }


# --- self-test -------------------------------------------------------------
def self_test() -> int:
    agent = {
        "id": "016", "name": "macos-demo", "version": "v5.0.0",
        "groups": ["default"],
        "host": {"architecture": "arm64", "hostname": "demo-macbook.local",
                 "os": {"name": "macOS", "platform": "darwin",
                        "type": "macos", "version": "26.7"}},
    }
    doc = {"collector": "file", "module": "fim",
           "data": {"event": {"type": "modified"},
                    "file": {"path": "/etc/hosts", "size": 213}}}

    buf = build_session(
        module="fim",
        indices=["wazuh-states-fim-files"],
        agent=agent,
        documents=[
            {"id": "abc123", "index": "wazuh-states-fim-files",
             "version": 7, "data": doc},
            {"id": "def456", "index": "wazuh-states-fim-files",
             "version": 1, "operation": Operation.Delete, "data": b"{}"},
        ],
    )
    print(f"buffer: {len(buf)} bytes")

    got = parse_session(buf)
    s, v = got["start"], got["values"]

    checks = [
        ("module", s["module"], "fim"),
        ("mode", s["mode"], Mode.ModuleDelta),
        ("index vector", s["index"], ["wazuh-states-fim-files"]),
        ("option", s["option"], Option.Sync),
        ("architecture", s["architecture"], "arm64"),
        ("hostname", s["hostname"], "demo-macbook.local"),
        ("osname", s["osname"], "macOS"),
        ("osplatform", s["osplatform"], "darwin"),
        ("ostype", s["ostype"], "macos"),
        ("osversion", s["osversion"], "26.7"),
        ("agentversion", s["agentversion"], "v5.0.0"),
        ("agentname", s["agentname"], "macos-demo"),
        ("agentid", s["agentid"], "016"),
        ("groups", s["groups"], ["default"]),
        ("cluster_name", s["cluster_name"], "wazuh"),
        ("value count", len(v), 2),
        ("value[0] id", v[0]["id"], "abc123"),
        ("value[0] index", v[0]["index"], "wazuh-states-fim-files"),
        ("value[0] version", v[0]["version"], 7),
        ("value[0] operation", v[0]["operation"], Operation.Upsert),
        ("value[0] data", json.loads(v[0]["data"]), doc),
        ("value[1] operation", v[1]["operation"], Operation.Delete),
        ("value[1] data", v[1]["data"], b"{}"),
    ]

    failed = 0
    for name, got_v, want in checks:
        good = got_v == want
        failed += not good
        print(f"  {'ok  ' if good else 'FAIL'} {name:<22} {got_v!r}"
              + ("" if good else f"  != {want!r}"))

    print("\nself-test", "passed" if not failed else f"FAILED ({failed})")
    return 0 if not failed else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    print(__doc__)
