package xmssmt

import (
	"encoding/binary"
	"fmt"
	goLog "log"
)

// Encodes the given uint64 into the buffer out in Big Endian
func encodeUint64Into(x uint64, out []byte) {
	if len(out)%8 == 0 {
		binary.BigEndian.PutUint64(out[len(out)-8:], x)
		for i := 0; i < len(out)-8; i += 8 {
			binary.BigEndian.PutUint64(out[i:i+8], 0)
		}
	} else {
		for i := len(out) - 1; i >= 0; i-- {
			out[i] = byte(x)
			x >>= 8
		}
	}
}

// Encodes the given uint64 as [outLen]byte in Big Endian.
func encodeUint64(x uint64, outLen int) []byte {
	ret := make([]byte, outLen)
	encodeUint64Into(x, ret)
	return ret
}

// Interpret []byte as Big Endian int.
func decodeUint64(in []byte) (ret uint64) {
	// TODO should we use binary.BigEndian?
	for i := 0; i < len(in); i++ {
		ret |= uint64(in[i]) << uint64(8*(len(in)-1-i))
	}
	return
}

type errorImpl struct {
	msg    string
	locked bool
	inner  error
}

func (err *errorImpl) Locked() bool { return err.locked }
func (err *errorImpl) Inner() error { return err.inner }

func (err *errorImpl) Error() string {
	if err.inner != nil {
		return fmt.Sprintf("%s: %s", err.msg, err.inner.Error())
	}
	return err.msg
}

// Formats a new Error
func errorf(format string, a ...interface{}) *errorImpl {
	return &errorImpl{msg: fmt.Sprintf(format, a...)}
}

// Formats a new Error that wraps another
func wrapErrorf(err error, format string, a ...interface{}) *errorImpl {
	return &errorImpl{msg: fmt.Sprintf(format, a...), inner: err}
}

type dummyLogger struct{}
type stdlibLogger struct{}

func (logger *dummyLogger) Logf(format string, a ...interface{}) {}

func (logger *stdlibLogger) Logf(format string, a ...interface{}) {
	goLog.Printf(format, a...)
}

var log Logger

type Logger interface {
	Logf(format string, a ...interface{})
}

// Enables logging to log package.  For more flexibility, see SetLogger().
func EnableLogging() {
	SetLogger(&stdlibLogger{})
}

// Enables logging.  Disable logging by passing nil.
//
// Use EnableLogging if you want to log to the log package.
func SetLogger(logger Logger) {
	if logger == nil {
		log = &dummyLogger{}
		return
	}
	log = logger
}

// Priority queue of uint32s
type uint32Heap []uint32

func (h uint32Heap) Min() uint32        { return h[0] }
func (h uint32Heap) Len() int           { return len(h) }
func (h uint32Heap) Less(i, j int) bool { return h[i] < h[j] }
func (h uint32Heap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *uint32Heap) Push(x interface{}) {
	*h = append(*h, x.(uint32))
}

func (h *uint32Heap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
