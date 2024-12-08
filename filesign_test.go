package hunting_sideload

import (
	"bytes"
	"context"
	_ "encoding/json"
	"log"
	"os"
	_ "path/filepath"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/suite"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	_ "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/types"
)

type FileSignTestSuite struct {
	suite.Suite
}

type testCase struct {
	description string
	args        *ordereddict.Dict
	expected    *ordereddict.Dict
}

var testCases = []testCase{
	{
		description: "Valid file signature",
		args: ordereddict.NewDict().
			Set("file_path", "C:\\Windows\\Temp").
			Set("sigcheck_path", "C:\\Program Files\\Velociraptor\\Tools\\sigcheck64.exe"),
	},
}

func (self *FileSignTestSuite) TestFileSignatures() {
	ctx := context.Background()
	scope := vql_subsystem.MakeScope()
	defer scope.Close()

	plugin := VertifyDLLPlugin{}

	for _, test_case := range testCases {
		log_collector := &bytes.Buffer{}
		scope.SetLogger(log.New(log_collector, "", 0))

		rows := []types.Row{}
		for row := range plugin.Call(ctx, scope, test_case.args) {
			rows = append(rows, row)
		}

		self.GreaterOrEqual(len(rows), 1, test_case.description)

		for _, result := range rows {
			dict := result.(*ordereddict.Dict)
			for key, value := range *dict.ToDict() {
				log.Printf("Key: %s, Value: %v", key, value)
			}
		}

		os.Stderr.Write(log_collector.Bytes())
	}
}

func TestFileSignPlugin(t *testing.T) {
	suite.Run(t, &FileSignTestSuite{})
}
