package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

func main() {

	BpfProgram := `

#include <bcc/proto.h>

typedef struct {
	u32 pid;
	char comm[128];
} execve_event_t ;

BPF_PERF_OUTPUT(execve_event);
int hello(void *ctx) {

	u64 pid = bpf_get_current_pid_tgid();

execve_event_t event ={
	.pid = pid >> 32,
};

bpf_get_current_comm(&event.comm,sizeof(event.comm));

execve_event.perf_submit(ctx,&event,sizeof(event));

return 0;

}
`

	type execve_event struct {
		Pid  uint32
		Comm [128]byte
	}

	BPFModule := bpf.NewModule(BpfProgram, []string{})
	// args = source of bpfprogram, cflags - []string

	defer BPFModule.Close()

	sig := make(chan os.Signal, 1)

	signal.Notify(sig, os.Interrupt)

	kprobe, err := BPFModule.LoadKprobe("hello")

	if err != nil {
		fmt.Printf("Failed to load kprobe: %s\n", err)
	}

	syscallName1 := bpf.GetSyscallFnName("execve")

	err = BPFModule.AttachKprobe(syscallName1, kprobe, -1)

	execveEventsTable := bpf.NewTable(0, BPFModule)

	dataRecieveChannel := make(chan []byte)
	lostchannel := make(chan uint64)
	pm, err := bpf.InitPerfMap(execveEventsTable, dataRecieveChannel, lostchannel)

	pm.Start()

	go func() {

		var eventsTable execve_event

		for {
			data := <-dataRecieveChannel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &eventsTable)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to decode received chroot event data: %s\n", err)
				continue
			}

			fmt.Println(eventsTable.Pid)
		}

	}()

	<-sig
	fmt.Println("stops here")
	pm.Stop()

}
