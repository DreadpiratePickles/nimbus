package cli

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/query"
	"github.com/spf13/cobra"
)

var queryFlags struct {
	engine, format string
	describe       bool
	named          string
	list           bool
}

var queryCmd = &cobra.Command{
	Use:   "query [SQL]",
	Short: "Query your cloud with SQL — zero-ETL views over findings, inventory, compliance and attack paths; Steampipe passthrough",
	Example: `  cloud-posture query "SELECT * FROM aws_s3_buckets WHERE public_access = true"
  cloud-posture query "SELECT entry_point, target, path_length FROM attack_path_summary WHERE target_type LIKE '%DATA%'"
  cloud-posture query "SELECT control_id, status, reason FROM cis_aws_benchmark WHERE status = 'FAIL'"
  cloud-posture query --describe
  cloud-posture query "select name from aws_s3_bucket" --engine steampipe   # live cloud via Steampipe`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		if queryFlags.describe {
			schema, err := query.Schema(st)
			if err != nil {
				return err
			}
			names := make([]string, 0, len(schema))
			for n := range schema {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				fmt.Printf("%s (%s)\n", n, strings.Join(schema[n], ", "))
			}
			return nil
		}
		if queryFlags.list || queryFlags.named != "" {
			exe := python(cfg)
			if exe == "" {
				return fmt.Errorf("the saved query library lives in the Python package (pip install -e python)")
			}
			pyArgs := []string{"-m", "nimbus", "query"}
			if queryFlags.list {
				pyArgs = append(pyArgs, "--list")
			} else {
				pyArgs = append(pyArgs, "--named", queryFlags.named)
			}
			out, err := runPython(cmd.Context(), exe, []string{"CLOUD_POSTURE_DB=" + st.Path()}, pyArgs...)
			fmt.Print(string(out))
			return err
		}
		if len(args) == 0 {
			return fmt.Errorf("provide a SQL statement, --describe, --list or --named <name>")
		}
		res, err := query.Run(context.Background(), st, strings.Join(args, " "), queryFlags.engine)
		if err != nil {
			return err
		}
		switch queryFlags.format {
		case "json":
			return output.JSON(os.Stdout, res)
		case "csv":
			w := csv.NewWriter(os.Stdout)
			w.Write(res.Columns)
			for _, r := range res.Rows {
				row := make([]string, len(r))
				for i, v := range r {
					row[i] = fmt.Sprint(v)
				}
				w.Write(row)
			}
			w.Flush()
			return nil
		default:
			output.Rows(os.Stdout, res.Columns, res.Rows)
			if res.Engine == "steampipe" {
				logf("(executed by steampipe)")
			}
			return nil
		}
	},
}

func init() {
	queryCmd.Flags().StringVar(&queryFlags.engine, "engine", "", "local|steampipe (default: auto — steampipe when the table is not local)")
	queryCmd.Flags().StringVarP(&queryFlags.format, "format", "f", "table", "table|json|csv")
	queryCmd.Flags().BoolVar(&queryFlags.describe, "describe", false, "list tables/views and columns")
	queryCmd.Flags().StringVar(&queryFlags.named, "named", "", "run a saved query from the compliance query library")
	queryCmd.Flags().BoolVar(&queryFlags.list, "list", false, "list saved queries")
	root.AddCommand(queryCmd)
}
