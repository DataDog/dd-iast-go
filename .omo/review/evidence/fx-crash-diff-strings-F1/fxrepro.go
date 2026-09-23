package fxfmtrepro

import "fmt"

type auditLevel string

func (auditLevel) String() string { return "AUDIT_OK" }

func FormatStringer(v string) string { return fmt.Sprintf("level=%s", auditLevel(v)) }

func SprintStringer(v string) string { return fmt.Sprint(auditLevel(v)) }

func FormatType(v string) string { return fmt.Sprintf("type=%T", v) }

func FormatZeroPrecision(v string) string { return fmt.Sprintf("x%.0sy", v) }

func FormatIndexSkip(v, clean string) string { return fmt.Sprintf("%[2]s", v, clean) }

func FormatControl(v string) string { return fmt.Sprintf("n=%d", len(v)) }

func FormatPositive(v string) string { return fmt.Sprintf("q=%s", v) }

func BuildQuery(v string) string {
	return fmt.Sprintf("SELECT * FROM t WHERE level='%s'", auditLevel(v))
}
