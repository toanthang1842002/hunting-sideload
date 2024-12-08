package hunting_sideload

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/Velocidex/ordereddict"
	_ "github.com/go-sql-driver/mysql"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
	"www.velocidex.com/golang/vfilter/types"
)

type DatabaseDLLQuery struct{}

func (self DatabaseDLLQuery) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:    "DatabaseDLL_query",
		Doc:     "Execute a MySQL query and check legitimate dll, return results",
		ArgType: type_map.AddType(scope, &MySQLArgs{}),
	}
}

type MySQLArgs struct {
	Host     string `vfilter:"required,field=host,doc=MySQL server host"`
	Port     string `vfilter:"optional,field=port,doc=MySQL server port"`
	User     string `vfilter:"required,field=user,doc=MySQL username"`
	Password string `vfilter:"required,field=password,doc=MySQL password"`
	Database string `vfilter:"required,field=database,doc=Database name"`
	Query    string `vfilter:"required,field=query,doc=SQL query to execute"`
}

func (self DatabaseDLLQuery) Call(
	ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) <-chan types.Row {

	output_chan := make(chan types.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor("DatabaseDLL_query", args)()

		arg := &MySQLArgs{}
		err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("mysql_query: %s", err.Error())
			return
		}

		if arg.Port == "" {
			arg.Port = "3306"
		}

		query_hash := fmt.Sprintf(`SELECT * FROM legitimate_dll where sha1 = '%s'`, arg.Query)
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
			arg.User, arg.Password, arg.Host, arg.Port, arg.Database)

		db, err := sql.Open("mysql", dsn)
		if err != nil {
			scope.Log("mysql_query connection error: %s", err.Error())
			return
		}
		defer db.Close()

		rows, err := db.QueryContext(ctx, query_hash)
		if err != nil {
			scope.Log("mysql_query execution error: %s", err.Error())
			return
		}
		defer rows.Close()
		if !rows.Next() {
			output_chan <- ordereddict.NewDict().Set("result", "NO").Set("row", "")
		}
		if rows.Next() {
			for rows.Next() {
				columns, _ := rows.Columns()
				values := make([]interface{}, len(columns))
				result := make(map[string]interface{})

				for i := range columns {
					values[i] = new(interface{})
				}

				if err := rows.Scan(values...); err != nil {
					continue
				}

				for i, col := range columns {
					if v := *(values[i].(*interface{})); v != nil {
						switch v := v.(type) {
						case []byte:
							result[col] = string(v)
						default:
							result[col] = v
						}
					}
				}

				output_chan <- ordereddict.NewDict().Set("result", "YES").Set("row", result)

				if ctx.Err() != nil {
					return
				}
			}
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&DatabaseDLLQuery{})
}
