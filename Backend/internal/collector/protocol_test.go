package collector

import "testing"

func TestDecodeFileEventIncludesTargetAndProcessChain(t *testing.T) {
	w := newBinWriter(256)
	w.writeU64(42)
	w.writeU8(EvtModify)
	w.writeStr("/home/user/ig_test/a.txt")
	w.writeStr("a.txt")
	w.writeU16(0)
	w.writeU8(MonEbpf)
	w.writeU32(1234)
	w.writeU32(1710000000)
	w.writeU64(100)
	w.writeU64(200)
	w.writeU8(1)
	w.writeU32(1000)
	w.writeU32(1200)
	w.writeStr("chmod")
	w.writeU8(1)
	w.writeU8(0)
	w.writeU32(1234)
	w.writeU32(1200)
	w.writeU32(1000)
	w.writeU32(0)
	w.writeU32(1200)
	w.writeU64(999000000)
	w.writeStr("bash")
	w.writeStr("pts/0")
	w.writeStr("/usr/bin/bash")
	w.writeStr("bash -c touch a.txt")

	ev, err := DecodeFileEvent(w.bytes())
	if err != nil {
		t.Fatalf("DecodeFileEvent failed: %v", err)
	}
	if ev.AgentID != 42 || ev.TargetDev != 100 || ev.TargetIno != 200 || !ev.Blocked {
		t.Fatalf("unexpected event target fields: %+v", ev)
	}
	if ev.UID != 1000 || ev.SID != 1200 || ev.Comm != "chmod" {
		t.Fatalf("unexpected actor fast fields: %+v", ev)
	}
	if ev.Chain.Depth != 1 || ev.Chain.Truncated || len(ev.Chain.Entries) != 1 {
		t.Fatalf("unexpected chain metadata: %+v", ev.Chain)
	}
	entry := ev.Chain.Entries[0]
	if entry.PID != 1234 || entry.PPID != 1200 || entry.UID != 1000 || entry.EUID != 0 || entry.SID != 1200 {
		t.Fatalf("unexpected chain entry ids: %+v", entry)
	}
	if entry.Comm != "bash" || entry.TTY != "pts/0" || entry.Exe != "/usr/bin/bash" || entry.Cmdline != "bash -c touch a.txt" {
		t.Fatalf("unexpected chain entry strings: %+v", entry)
	}
}

func TestDecodeFileEventRequiresTargetAndProcessChainMetadata(t *testing.T) {
	w := newBinWriter(64)
	w.writeU64(42)
	w.writeU8(EvtModify)
	w.writeStr("/tmp/a")
	w.writeStr("a")
	w.writeU16(0)
	w.writeU8(MonEbpf)
	w.writeU32(1234)
	w.writeU32(1710000000)

	if _, err := DecodeFileEvent(w.bytes()); err == nil {
		t.Fatal("DecodeFileEvent succeeded without target/process-chain metadata")
	}
}
