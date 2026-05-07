package cmd

import (
	"os"
	"testing"
)

func TestExecute_UnknownCommand(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"gh-relay", "unknown-cmd"}
	err := Execute()
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestExecute_Version(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"gh-relay", "version"}
	err := Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestExecute_NoArgs(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"gh-relay"}
	err := Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestExecute_HelpFlag(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"gh-relay", "--help"}
	err := Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestExecute_HelpFlagShort(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"gh-relay", "-h"}
	err := Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestExecute_HelpCommand(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"gh-relay", "help"}
	err := Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}