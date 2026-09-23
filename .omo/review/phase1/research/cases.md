# Orchestrion research PR #858: propagation coverage cases

Source: `DataDog/orchestrion` branch `eliottness/iast-testing`. The expected
outcome column reflects each case's `Want` declaration: `report` means an
`os.Open`/`os.OpenFile` report is expected with the listed value and ranges;
`no report` means the case declares no report.

| Case ID | Go construct exercised | Expected taint outcome | Category |
|---|---|---|---|
| 000 byte reconstruction | `string` to `[]byte`, byte index, byte-to-string reconstruction | report `byte-s`, range `[5,6)` | scalar |
| 000 constant concat | constant string concatenation after unused environment source | no report | string op |
| 000 shadowed append | locally shadowed `append` function | no report | bytes op |
| 000 strconv quote clean output | `strconv.Quote` on clean literal | no report | string op |
| 000 strings builder clean write | `strings.Builder.WriteString`, `Write`, `String` with clean inputs | no report | buffer |
| 002 empty or clean source | empty `os.Getenv` result and clean literal passed to `os.Open` | no report | string op |
| 003 equal clean literal | clean literal equal in content to sourced value | no report | string op |
| 005 conditional phi merge | conditional assignment merging clean and tainted strings | report `secret`, range `[0,6)` | control-flow |
| 008 static recursion | recursive direct call | report `secret`, range `[0,6)` | control-flow |
| 009 dynamic recursion and stack growth | recursive function value and stack growth | report `secret`, range `[0,6)` | control-flow |
| 010 deferred dynamic call cleanup | function value call with deferred call | report `secret`, range `[0,6)` | control-flow |
| 011 panic/recover transition cleanup | panic/recover loop then ordinary function call | report `secret`, range `[0,6)` | control-flow |
| 012 recovered named return | panic recovery assigning a named return from `os.Getenv` | report `secret`, range `[0,6)` | control-flow |
| 013 address-taken string parameter | address-taking and dereference of string parameter | report `secret`, range `[0,6)` | string op |
| 014 tainted parameter ignored, clean return | function ignores tainted parameter and returns clean string | no report | control-flow |
| 017 interface receiver stays clean | interface dispatch with clean receiver result | no report | control-flow |
| 019 global string assignment | sourced string assignment to global variable | report `secret`, range `[0,6)` | container |
| 023 omitted-bound or three-index slice | string slicing with omitted bound and three-index slice | report `win-sec`, range `[4,7)` | string op |
| 024 string byte conversion | string-to-byte conversion and byte/string use | report `secret`, range `[0,6)` | bytes op |
| 025 rune conversion | string-to-rune conversion and string reconstruction | report `rune-secret`, range `[5,11)` | scalar |
| 026 append scalar byte | append a tainted scalar byte | report `secret!`, range `[0,6)` | scalar |
| 027 append string bytes | append bytes converted from a tainted string | report `append-secret`, range `[7,13)` | bytes op |
| 028 generic byte append | generic function appending to a byte slice | report `generic-bytes-secret!`, range `[14,20)` | bytes op |
| 029 copy string bytes | copy string bytes into a byte slice | report `copy-secret`, range `[5,11)` | bytes op |
| 030 clear bytes | `clear` on tainted byte slice | no report | bytes op |
| 031 clean byte overwrite | clean byte overwrite of tainted byte | no report | bytes op |
| 032 dirty byte assignment | tainted byte assigned into byte slice | report `assigned-s`, range `[9,10)` | bytes op |
| 033 named byte reconstruction | named byte type and byte-to-string reconstruction | report `target-s`, range `[7,8)` | scalar |
| 033 string byte reconstruction | string-to-byte conversion and indexed reconstruction | report `scalar-s`, range `[7,8)` | scalar |
| 034 local byte | tainted byte stored in local scalar and reconstructed | report `local-byte-s`, range `[11,12)` | scalar |
| 035 local rune | tainted rune stored in local scalar and reconstructed | report `local-rune-s`, range `[11,12)` | scalar |
| 036 scalar channel | scalar byte passed through channel | report `s` twice, range `[0,1)` each | container |
| 036 scalar direct call | scalar byte passed through direct function call | report `s` twice, range `[0,1)` each | scalar |
| 036 scalar map | scalar byte passed through map | report `s` twice, range `[0,1)` each | container |
| 037 strings clone | `strings.Clone` | report `clone-secret`, range `[6,12)` | string op |
| 038 bytes clone | `bytes.Clone` | report `bytes-secret`, range `[6,12)` | bytes op |
| 039 strings replace | `strings.Replace` | report `replace-secret`, range `[8,14)` | string op |
| 040 strings replace all | `strings.ReplaceAll` | report `replace-all-sEcrEt`, ranges `[12,13)`, `[14,16)`, `[17,18)` | string op |
| 041 strings repeat | `strings.Repeat` | report `repeat-secretsecret`, range `[7,19)` | string op |
| 042 strings upper | `strings.ToUpper` | report `upper-SECRET`, range `[6,12)` | string op |
| 045 strings join | `strings.Join` | report `join-secret`, range `[5,11)` | string op |
| 046 fmt sprintf | `fmt.Sprintf` with tainted input | report `fmt-secret`, range `[0,10)` | string op |
| 047 fmt map | `fmt.Sprintf` formatting a map containing tainted value | report `map-map[value:secret]`, range `[0,21)` | container |
| 048 filepath join | `filepath.Join` | report `/tmp/secret`, range `[0,11)` | string op |
| 049 strconv quote fresh output | `strconv.Quote` on tainted input | report `"secret"` (quoted), range `[0,8)` | string op |
| 051 fresh allocation in uninstrumented dependency | tainted input passed through fresh-string dependency function | report `secret`, range `[0,6)` | string op |
| 052 named conversions | named string/byte conversions | report `named-secret`, range `[6,12)` | bytes op |
| 053 generic string concat | generic string concatenation | report `generic-secret`, range `[8,14)` | string op |
| 054 named slice append | append using named byte-slice type | report `mixed-secret`, range `[6,12)` | bytes op |
| 055 named string append | named string append | report `named-append-secret`, range `[13,19)` | bytes op |
| 056 named copy | copy using named byte-slice type | report `named-copy-secret`, range `[11,17)` | bytes op |
| 057 named octets | named byte slice and conversion | report `octets-secret`, range `[7,13)` | bytes op |
| 058 strings builder | `strings.Builder` with tainted input | report `builder-secret`, range `[8,14)` | buffer |
| 059 strings builder write | `strings.Builder` write methods with tainted input | report `builder-secret`, range `[8,14)` | buffer |
| 061 buffer write string | `bytes.Buffer.WriteString` | report `buffer-secret`, range `[7,13)` | buffer |
| 062 buffer bytes view | `bytes.Buffer.Bytes` view | report `view-secret`, range `[5,11)` | buffer |
| 064 method-value buffer grow | `bytes.Buffer.Grow` called as method value | report `secret`, range `[0,6)` | buffer |
| 065 method-expression buffer grow | `bytes.Buffer.Grow` called as method expression | report `secret`, range `[0,6)` | buffer |
| 066 buffer next | `bytes.Buffer.Next` | report `next-secret`, range `[5,11)` | buffer |
| 067 buffer truncate | `bytes.Buffer.Truncate` | report `truncate-sec`, range `[9,12)` | buffer |
| 068 buffer reset | `bytes.Buffer.Reset` on tainted content | no report | buffer |
| 069 new buffer string | `bytes.NewBufferString` | report `constructed-secret`, range `[12,18)` | buffer |
| 071 buffer alias dirty write | write tainted content through a buffer alias | report `alias-s`, range `[6,7)` | buffer |
| 072 buffer alias clean overwrite | clean overwrite through a buffer alias | no report | buffer |
| 073 buffer read | `bytes.Buffer.Read` | report `secret`, range `[0,6)` | buffer |
| 073 buffer read bytes | `bytes.Buffer.Read` into byte slice | report `secret\n`, range `[0,6)` | buffer |
| 073 buffer read from | `bytes.Buffer.ReadFrom` | report `prefix-secret`, range `[7,13)` | buffer |
| 073 buffer read string | `bytes.Buffer.ReadString` | report `secret\n`, range `[0,6)` | buffer |
| 074 buffer write byte or rune | `bytes.Buffer.WriteByte` and `WriteRune` | report `s` twice, range `[0,1)` each | buffer |
| 077 unbuffered channel across goroutines | unbuffered channel send/receive across goroutines | report `secret`, range `[0,6)` | container |
| 078 buffered channel survives gc pressure | buffered channel transport with GC pressure | report `secret`, range `[0,6)` | GC |
| 079 select buffered send | buffered channel send selected with `select` | report `secret`, range `[0,6)` | control-flow |
| 080 select blocking receive | blocking receive selected with `select` | report `secret`, range `[0,6)` | control-flow |
| 081 select blocking send | blocking send selected with `select` | report `secret`, range `[0,6)` | control-flow |
| 082 closed channel returns clean zero string | receive zero string from closed channel | no report | container |
| 083 standalone buffered receive in select | standalone buffered receive in `select` | report `secret`, range `[0,6)` | control-flow |
| 087 map growth and rehash | map insertion, growth, and rehash | report `secret`, range `[0,6)` | container |
| 088 map comma-ok lookup | map lookup with comma-ok result | report `secret`, range `[0,6)` | container |
| 089 map range value | map range over tainted value | report `secret`, range `[0,6)` | container |
| 090 maps clone | map cloning | report `secret`, range `[0,6)` | container |
| 091 map overwrite with clean value | overwrite tainted map value with clean value | no report | container |
| 092 map delete | delete map entry holding tainted value | no report | container |
| 093 map clear | `clear` map containing tainted value | no report | container |
| 094 generic small-key map | generic map with small key type | report `secret`, range `[0,6)` | container |
| 095 reflection map delete and clean overwrite | `reflect.Value.SetMapIndex` delete and clean overwrite | no report | reflect |
| 097 struct field transport | tainted string assigned to and read from struct field | report `secret`, range `[0,6)` | container |
| 102 non-recursive stack move with live tainted frame | stack move with live tainted frame | report `secret`, range `[0,6)` | GC |
| 103 stack reuse clears old labels | stack reuse and subsequent tainted source | report `secret`, range `[0,6)` | GC |
| 104 gc sweep clears heap shadow | heap shadow after GC sweep | report `case104-`, range `[8,43)` | GC |
| 122 open file sink | direct `os.OpenFile` sink call | report `secret`, range `[0,6)` | sink |
| 126 multiple exact source root sets | concatenate two sources and apply `strings.ToUpper` | report `ALPHABETA`, ranges `[0,9)`, `[0,9)` | string op |
| 131 url query escape fresh string | `url.QueryEscape` fresh string | report `%2Fsecret`, range `[0,9)` | string op |
| 132 regexp replaceallstring fresh string | `regexp.ReplaceAllString` | report `secret-public`, range `[0,13)` | string op |
| 133 base64 encode to string | `base64.StdEncoding.EncodeToString` | report `c2VjcmV0`, range `[0,8)` | string op |
| 134 json marshal bytes | `json.Marshal` then byte-to-string conversion | report `{"path":"secret"}`, range `[0,17)` | bytes op |
| 135 xml marshal bytes | `xml.Marshal` then byte-to-string conversion | report `<payload><Path>secret</Path></payload>`, range `[0,38)` | bytes op |
| 136 bufio reader read string | `bufio.Reader.ReadString` | report `secret\n`, range `[0,6)` | string op |
| 137 database sql scan driver bytes | `database/sql.Rows.Scan` from driver byte slice | report `secret`, range `[0,6)` | bytes op |
| 138 io copy into bytes buffer | `io.Copy` into `bytes.Buffer` | report `secret`, range `[0,6)` | buffer |
| 139 buffer write to bytes buffer | `bytes.Buffer.WriteTo` pointer and value receiver cases | reports `pointer-dirty-secret` `[14,20)` and `value-dirty-secret` `[12,18)` | buffer |
| 141 no inline prebuilt fresh string function | non-inlined dependency returns fresh string from input | report `secret`, range `[0,6)` | string op |
| 142 function call launched with go | `go` statement passes tainted string argument to goroutine | report `secret`, range `[0,6)` | control-flow |
| 143 no-inline function returns two strings | non-inlined function returns two string results | two reports `secret`, range `[0,6)` each | string op |
| 144 string element store and load | store/load tainted string in `[]string` | report `secret`, range `[0,6)` | container |
| 145 tainted string used as map key and ranged back | tainted map key and map range | report `secret`, range `[0,6)` | container |
| 146 reflection map delete isolated check | reflective map deletion | no report | reflect |
| 147 reflection map clean overwrite isolated check | reflective map overwrite with clean value | no report | reflect |
| 148 named rune slice conversion | named rune slice conversion and string reconstruction | report `named-rune-secret`, range `[11,17)` | scalar |
| 152 strings cut alias result | `strings.Cut` alias result | report `secret`, range `[0,6)` | string op |
| 153 strings trimprefix alias result | `strings.TrimPrefix` alias result | report `secret`, range `[0,6)` | string op |
| 154 strings split slice of string views | `strings.Split` returns string views stored in slice | reports `alpha-value` `[0,11)` and `beta-value` `[0,10)` | string op |
| 155 regexp findstring alias-like result | `regexp.FindString` alias-like result | report `secret`, range `[0,6)` | string op |
| 156 path clean fresh string | `path.Clean` fresh string | report `secret`, range `[0,6)` | string op |
| 157 two independently tainted inputs concatenated | concatenate two independently sourced strings | report `alphabeta`, ranges `[0,5)`, `[5,9)` | string op |

## Shadow fixture `cases.json` names

The following fixture directories contain `cases.json` entries. Multiple names
are separated by semicolons when one fixture file defines multiple entries.

| Fixture directory | Case name(s) |
|---|---|
| addressparam | address-taken parameter |
| appendscalarbytetotaintedby | append scalar byte to tainted bytes |
| appendstringbyteswithsource | append string bytes with source spread |
| base64encodetostring | base64 encode to string; base64 encode to string clean; base64 encode to string disabled |
| broadcontrolflow | broad-implicit-control-flow; broad-implicit-control-flow-disabled; broad-implicit-control-flow-mismatch |
| bufferbytesaliasgetscleanov | buffer bytes alias gets clean overwrite |
| bufferbytesaliasgetsdirtyby | buffer bytes alias gets dirty byte write |
| bufferreadreadbytreadstrorr | buffer read string |
| bufferwritebyteorwriterune | buffer write byte or rune; buffer write byte or rune clean; buffer write byte or rune disabled |
| bufioreaderreadstring | bufio reader read string |
| bytesbuffernextshiftsranges | bytes buffer next shifts ranges |
| bytesbufferresetclearstaint | bytes buffer reset clears taint; bytes buffer reset control without reset |
| bytesbuffertruncate | bytes buffer truncate |
| bytesbufferwritebyteandbyte | bytes buffer write bytes and view |
| bytesbufferwritestandstring | bytes buffer write string |
| bytesbufferwritetointocopyp | buffer write to another buffer |
| bytescalarthroughlocalvariable | byte scalar through local variable |
| bytesclone | bytes clone |
| bytesnewbufferbyte | bytes new buffer from bytes |
| bytesnewbufferstring | bytes new buffer string |
| call | static call |
| channel | buffered channel |
| channelgc | buffered channel GC |
| channelunbuffered | unbuffered channel |
| channelzero | zero-sized channel |
| cleanbyteoverwritesdirtybyte | clean byte overwrites dirty byte |
| clearbyteremovestaint | clear bytes removes taint; clear bytes control without clear |
| closurevalue | closure environment |
| copybytestring | copy bytes from string |
| databassqlscanfromdriverbyt | sql scan driver bytes into string |
| directbytesbuffergrow | direct bytes buffer grow |
| directstringbyteindexreconstruction | direct string byte index reconstruction |
| dirtyindexedbyteassignedtocleanslice | dirty indexed byte assigned into clean slice |
| dynamicdefer | dynamic defer |
| dynamicrecursion | dynamic recursion |
| equalbytesonedirtyandonecl | equal bytes, one dirty and one clean |
| exactbyteranges | exact-byte-ranges; exact-byte-ranges-disabled |
| exactsourceoccurrenceidentity | exact-source-occurrence-identity; exact-source-occurrence-identity-disabled |
| filepathjoin | filepath join; filepath join clean; filepath join disabled |
| fmtsprintfwithmapaggregate | fmt sprintf with map aggregate; fmt sprintf with map aggregate clean; fmt sprintf with map aggregate disabled |
| fmtsprintfwithstring | fmt sprintf with string |
| fmtsprintfwithstructaggregate | fmt sprintf with struct aggregate; fmt sprintf with struct aggregate clean; fmt sprintf with struct aggregate disabled |
| freshallocatinuninstrdepende | fresh allocation in uninstrumented dependency |
| functioncalllaunchedwithgo | patched function call launched with go |
| functionvalue | function value |
| genericbytesliceappend | generic byte-slice append; generic byte-slice append clean; generic byte-slice append disabled |
| genericstringconcat | generic string concat; generic string concat clean; generic string concat disabled |
| globalstringassignment | global-string-assignment; global-string-assignment-disabled |
| heapreuse | heap address reuse; heap reuse race |
| indepenconcurrrangeregistr | independent concurrent registrations |
| indirectosfunctionvalues | indirect-os-getenv-and-open-function-values; indirect-os-getenv-and-open-function-values-disabled |
| interfacecall | interface dispatch |
| interfacereceiver | interface receiver isolation |
| iocopyintobytesbuffer | io copy into bytes buffer |
| jsonmarshalbytes | json marshal bytes |
| localcopy | disabled; clean; local copy |
| mapassign | map assignment |
| mapcases | map lifecycle; map race |
| mapgenericsmall | generic small map |
| mapgrowth | map growth |
| mapvalue | map literal |
| methodexpresspromoteorinterf | method expression buffer grow |
| methodvaluebuffergrow | method value buffer grow |
| multiplesourcerootsets | multiple-exact-source-root-sets; multiple-exact-source-root-sets-disabled |
| namedbytesliceappend | named byte-slice append; named byte-slice append clean; named byte-slice append disabled |
| namedoctets | named octets; named octets clean; named octets disabled |
| namedrunesliceconversion | named-rune-slice-conversion; named-rune-slice-conversion-disabled |
| namedstringappend | named string append; named string append clean; named string append disabled |
| namedstringcopy | named string copy; named string copy clean; named string copy disabled |
| noinlinefunctionreturnstwostrings | noinline-function-returns-two-strings; noinline-function-returns-two-strings-disabled |
| noinlineprebuiltfreshstring | no inline prebuilt fresh string function; no inline prebuilt fresh string function clean; no inline prebuilt fresh string function disabled |
| noinlineprebuiltidentity | no inline prebuilt identity function; no inline prebuilt identity function clean; no inline prebuilt identity function disabled |
| noopbuffergrowavoidscapacit | patched no-op buffer grow |
| omittedboundorthreeindexsli | omitted-bound or three-index slice |
| panic | panic cleanup |
| pathcleanfreshstring | path clean fresh string; path clean fresh string clean; path clean fresh string disabled |
| phi | phi |
| reassignedlocalfunctionalias | reassigned-local-getenv-alias-stays-clean; reassigned-local-getenv-alias-stays-clean-disabled |
| recoverreturn | recovered return |
| recursion | static recursion |
| reflectmapcleanoverwriisolat | patched reflection map clean overwrite |
| reflectmapdeleteisolatecheck | patched reflection map delete |
| regexpfindstraliaslikeresult | patched regexp find string |
| regexpreplacefreshstring | regexp replace all string |
| registrcategorreaches65536r | patched prototype under 65536 tainted values |
| runescalarthroughlocalvariable | rune scalar through local variable |
| scalarcallmapchannel | scalar call map channel; scalar call map channel disabled; scalar call map channel race |
| selectcases | select matrix; select clean; select race |
| selectchannel | select over buffered and blocked channels; select over buffered and blocked channels clean; select over buffered and blocked channels disabled |
| standalbufferereceiveinselec | patched standalone buffered receive in select |
| strconvquotefreshoutput | strconv quote fresh output; strconv quote fresh output clean; strconv quote fresh output disabled |
| stringconcatewithexactranges | string concatenation with exact ranges |
| stringsbuildergrowrelocation | strings builder grow relocation |
| stringsbuilderwritebyte | strings builder write bytes |
| stringsbuilderwritestandstri | strings builder write string |
| stringsclone | strings clone |
| stringscutaliasresult | patched strings cut alias result |
| stringsjoin | strings join |
| stringsliceelementstoreload | string-slice-element-store-and-load; string-slice-element-store-and-load-disabled |
| stringsmap | strings map |
| stringsrepeat | strings repeat |
| stringsreplace | strings replace |
| stringsreplaceall | strings replace all |
| stringssplitsliceofstringvi | patched strings split slice of views |
| stringstolower | strings to lower |
| stringstoupper | strings to upper |
| stringstrimprefixaliasresult | patched strings trim prefix alias result |
| stringtobytetostring | string to bytes to string |
| stringtorunetostring | string to runes to string |
| taintedstringusedasmapkeya | patched tainted string as map key |
| twoindepentaintedinputsconca | patched two tainted inputs concatenated |
| twoindexstringorbyteslice | two-index string or byte slice |
| unnamedparam | unnamed parameters |
| urlqueryescapefreshstring | url query escape fresh string; url query escape fresh string clean; url query escape fresh string disabled |
| xmlmarshalbytes | xml marshal bytes |
