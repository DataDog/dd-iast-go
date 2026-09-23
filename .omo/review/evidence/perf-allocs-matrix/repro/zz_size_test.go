// Review reproducer (perf-allocs-matrix). Not part of the repository.
package spans

import (
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model"
)

func TestReproAnnotationSize(t *testing.T) {
	t.Logf("sizeof(Annotation)=%d bytes sizeof(model.Event)=%d bytes", unsafe.Sizeof(Annotation{}), unsafe.Sizeof(model.Event{}))
}
