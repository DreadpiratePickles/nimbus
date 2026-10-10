package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/spf13/cobra"
)

var convertFlags struct {
	from, to, out string
}

// convertCmd re-renders a findings file between formats (internal/output.Convert): pure, no
// database, no network.
var convertCmd = &cobra.Command{
	Use:   "convert <file|->",
	Short: "Convert findings between formats: nimbus JSON, OCSF 1.6, SARIF, ASFF → json|sarif|ocsf|asff|gitlab|junit|csv|html",
	Example: `  cloud-posture convert findings.json --to ocsf > findings.ocsf.json
  cloud-posture convert results.sarif --to gitlab -o gl-sast-report.json
  cloud-posture convert prowler.ocsf.json --from ocsf --to junit -o junit.xml
  cloud-posture scan -o json | cloud-posture convert - --to asff`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if convertFlags.to == "" {
			return fmt.Errorf("--to is required (one of %s)", strings.Join(output.ConvertFormats(), ", "))
		}
		var data []byte
		var err error
		// Both inputs go through the convert cap (output.MaxConvertInput): reading stops at the
		// cap instead of buffering an arbitrarily large file (verify-4 LOW).
		if args[0] == "-" {
			data, err = output.ReadConvertInput(os.Stdin)
		} else {
			var f *os.File
			if f, err = os.Open(args[0]); err == nil {
				data, err = output.ReadConvertInput(f)
				f.Close()
			}
		}
		if err != nil {
			return err
		}
		out, err := output.Convert(data, convertFlags.from, convertFlags.to)
		if err != nil {
			return err
		}
		if convertFlags.out == "" || convertFlags.out == "-" {
			_, err = os.Stdout.Write(out)
			return err
		}
		if err := os.WriteFile(convertFlags.out, out, 0o644); err != nil {
			return err
		}
		logf("%s written (%s → %s)", convertFlags.out, firstNonEmpty(convertFlags.from, "auto"), convertFlags.to)
		return nil
	},
}

func init() {
	f := convertCmd.Flags()
	f.StringVar(&convertFlags.from, "from", "auto", "input format: auto|"+strings.Join(output.ConvertInputs(), "|"))
	f.StringVar(&convertFlags.to, "to", "", "output format: "+strings.Join(output.ConvertFormats(), "|"))
	f.StringVarP(&convertFlags.out, "output", "o", "", "write to this file instead of stdout")
	root.AddCommand(convertCmd)
}
