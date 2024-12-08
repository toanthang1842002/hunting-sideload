package hunting_sideload

import (
	"context"
	"log"
	"os"
	"testing"
	"www.velocidex.com/golang/vfilter/types"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/suite"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"github.com/toanthang1842002/hunting-sideload"
)

type MySQLTestSuite struct {
	suite.Suite
}

func (self *MySQLTestSuite) TestMySQLQuery() {
	ctx := context.Background()
	scope := vql_subsystem.MakeScope()
	scope.SetLogger(log.New(os.Stderr, "", 0))
	defer scope.Close()
	//host="localhost",
	//	user="root",
	//	password="T@iga184",
	//	database="dll_database"
	//legitimate_dll
	plugin := &VertifyDLLPlugin{}
	args := ordereddict.NewDict().
		Set("dll_name", "127.0.0.1").
		Set("dll_path", "root").
		Set("yaml_folder", "T@iga184").
		Set("sigcheck_path", "dll_database")

	rows := []types.Row{}
	for row := range plugin.Call(ctx, scope, args) {
		rows = append(rows, row)
	}
	for _, result := range rows {
		dict := result.(*ordereddict.Dict)
		for key, value := range *dict.ToDict() {
			log.Printf("Key: %s, Value: %v", key, value)
		}
	}
}

func TestMySQLPlugin(t *testing.T) {
	suite.Run(t, &MySQLTestSuite{})
}
