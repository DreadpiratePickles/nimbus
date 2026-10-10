package cli

import (
	"strconv"

	"github.com/DreadpiratePickles/nimbus/internal/integrations"
)

// privateSinksFlag is `--allow-private-sinks`: setting it calls integrations.SetAllowPrivateSinks
// (the same switch as NIMBUS_ALLOW_PRIVATE_SINKS=1). Link-local and metadata addresses stay refused.
type privateSinksFlag struct{ v bool }

func (f *privateSinksFlag) String() string   { return strconv.FormatBool(f.v) }
func (f *privateSinksFlag) Type() string     { return "bool" }
func (f *privateSinksFlag) IsBoolFlag() bool { return true }
func (f *privateSinksFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	f.v = v
	integrations.SetAllowPrivateSinks(v)
	return nil
}

func init() {
	fl := root.PersistentFlags().VarPF(&privateSinksFlag{}, "allow-private-sinks", "", "allow alert/ticket sink URLs on private addresses (RFC 1918, ULA, CGNAT); metadata and link-local stay refused (also NIMBUS_ALLOW_PRIVATE_SINKS=1)")
	fl.NoOptDefVal = "true"
}
