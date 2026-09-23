package store

import (
	"testing"
	"unsafe"
)

func TestF2Sizes(t *testing.T) {
	t.Logf("Snapshot=%d WriterRef=%d [MaxSnapshotOwners]WriterRef=%d owner=%d MaxOwners=%d",
		unsafe.Sizeof(Snapshot{}), unsafe.Sizeof(WriterRef{}), unsafe.Sizeof([MaxSnapshotOwners]WriterRef{}), unsafe.Sizeof(owner{}), MaxOwners)
}
