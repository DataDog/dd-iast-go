package conv

type ID string

// rebuild marker 2
func Raw(id ID) []byte { return []byte(id) }
