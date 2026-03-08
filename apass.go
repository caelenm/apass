package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/term"
)

type Entry struct {
	Account  string `json:"account"`
	Username string `json:"username"`
	Password string `json:"password"`
	Edited   string `json:"edited"`
}
type Contact struct {
	Name   string `json:"name"`
	PubKey string `json:"pubkey"`
}
type Vault struct {
	Entries  []Entry   `json:"entries"`
	Contacts []Contact `json:"contacts"`
}

var (
	dir       = ".apass"
	keyFile   = filepath.Join(dir, "key.age")
	vaultFile = filepath.Join(dir, "vault.age")
)

func main() {
	v, id, rec, err := unlock()
	if err != nil {
		die(err)
	}
	fmt.Println("Vault :", abs(vaultFile))
	fmt.Println("PubKey:", rec.String())

	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("apass> ")
		line, err := in.ReadString('\n')
		if err != nil {
			fmt.Println()
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "-----BEGIN AGE ENCRYPTED FILE-----") {
			msg := line + "\n"
			for {
				x, err := in.ReadString('\n')
				if err != nil {
					break
				}
				msg += x
				if strings.TrimSpace(x) == "-----END AGE ENCRYPTED FILE-----" {
					break
				}
			}
			out, err := decryptArmored(msg, id)
			if err != nil {
				fmt.Println("decrypt failed:", err)
			} else {
				fmt.Println(out)
			}
			continue
		}

		f := strings.Fields(line)
		cmd := f[0]
		arg := ""
		if len(f) > 1 {
			arg = strings.Join(f[1:], " ")
		}

		switch cmd {
		case "ls":
			list(v)
		case "cat":
			if arg == "" {
				fmt.Println("cat ACCOUNT")
				continue
			}
			show(v, arg)
		case "sort":
			if arg == "" {
				arg = "AZ"
			}
			if err := sortVault(v, arg); err != nil {
				fmt.Println(err)
				continue
			}
			if err := saveVault(v, rec); err != nil {
				fmt.Println("save failed:", err)
			}
		case "add":
			if strings.HasPrefix(arg, "contact ") {
				name := strings.TrimSpace(strings.TrimPrefix(arg, "contact "))
				if name == "" {
					fmt.Println("add contact NAME")
					continue
				}
				if err := addContact(v, name, in); err != nil {
					fmt.Println(err)
					continue
				}
			} else {
				if err := addEntry(v, in); err != nil {
					fmt.Println(err)
					continue
				}
			}
			if err := saveVault(v, rec); err != nil {
				fmt.Println("save failed:", err)
			}
		case "edit":
			if arg == "" {
				fmt.Println("edit ACCOUNT")
				continue
			}
			if err := editEntry(v, arg, in); err != nil {
				fmt.Println(err)
				continue
			}
			if err := saveVault(v, rec); err != nil {
				fmt.Println("save failed:", err)
			}
		case "del":
			if arg == "" {
				fmt.Println("del ACCOUNT|contact NAME")
				continue
			}
			if strings.HasPrefix(arg, "contact ") {
				name := strings.TrimSpace(strings.TrimPrefix(arg, "contact "))
				if confirm(in, "Delete contact "+name+"?") {
					delContact(v, name)
					if err := saveVault(v, rec); err != nil {
						fmt.Println("save failed:", err)
					}
				} else {
					fmt.Println("cancelled")
				}
			} else {
				if confirm(in, "Delete entry "+arg+"?") {
					delEntry(v, arg)
					if err := saveVault(v, rec); err != nil {
						fmt.Println("save failed:", err)
					}
				} else {
					fmt.Println("cancelled")
				}
			}
		case "send":
			if arg == "" {
				fmt.Println("send CONTACT")
				continue
			}
			if err := sendTo(v, arg, in); err != nil {
				fmt.Println(err)
			}
		case "pubkey":
			fmt.Println(rec.String())
		case "lock":
			clearScreen()
			nv, nid, nrec, err := unlock()
			if err != nil {
				fmt.Println("unlock failed:", err)
				continue
			}
			v, id, rec = nv, nid, nrec
			fmt.Println("Vault :", abs(vaultFile))
			fmt.Println("PubKey:", rec.String())
		case "export":
			if err := exportVault(v, in, arg); err != nil {
				fmt.Println(err)
			}
		case "help":
			fmt.Println("ls | cat ACCOUNT | sort AZ|ZA|Date | add | add contact NAME | edit ACCOUNT | del ACCOUNT | del contact NAME | send NAME | pubkey | lock | export [file] | exit")
		case "exit", "quit":
			return
		default:
			fmt.Println("ls | cat ACCOUNT | sort AZ|ZA|Date | add | add contact NAME | edit ACCOUNT | del ACCOUNT | del contact NAME | send NAME | pubkey | lock | export [file] | exit")
		}
	}
}

func unlock() (*Vault, *age.X25519Identity, *age.X25519Recipient, error) {
	_ = os.MkdirAll(dir, 0700)
	fmt.Println("Key   :", abs(keyFile))
	fmt.Println("Vault :", abs(vaultFile))

	if !exists(vaultFile) {
		fmt.Println("No database found in current directory.")
		fmt.Print("Set a new master password: ")
		pw1, err := readPassword()
		if err != nil {
			return nil, nil, nil, err
		}
		fmt.Print("Confirm master password: ")
		pw2, err := readPassword()
		if err != nil {
			return nil, nil, nil, err
		}
		if pw1 == "" || pw1 != pw2 {
			return nil, nil, nil, errors.New("passwords did not match or were empty")
		}
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, nil, nil, err
		}
		if err := encryptWithPassword([]byte(id.String()+"\n"), pw1, keyFile); err != nil {
			return nil, nil, nil, err
		}
		v := &Vault{Entries: []Entry{}, Contacts: []Contact{}}
		if err := saveVault(v, id.Recipient()); err != nil {
			return nil, nil, nil, err
		}
		fmt.Println("New vault created.")
		return v, id, id.Recipient(), nil
	}

	fmt.Println("PLEASE ENTER YOUR PASSWORD")
	fmt.Print("> ")
	pw, err := readPassword()
	if err != nil {
		return nil, nil, nil, err
	}
	keyData, err := decryptWithPassword(keyFile, pw)
	if err != nil {
		return nil, nil, nil, errors.New("unlock failed")
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(keyData)))
	if err != nil {
		return nil, nil, nil, err
	}
	vb, err := decryptWithIdentity(vaultFile, id)
	if err != nil {
		return nil, nil, nil, err
	}
	var v Vault
	if len(vb) > 0 {
		if err := json.Unmarshal(vb, &v); err != nil {
			return nil, nil, nil, err
		}
	}
	if v.Entries == nil {
		v.Entries = []Entry{}
	}
	if v.Contacts == nil {
		v.Contacts = []Contact{}
	}
	fmt.Println("vault unlocked!")
	return &v, id, id.Recipient(), nil
}

func saveVault(v *Vault, r *age.X25519Recipient) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return err
	}
	if _, err = w.Write(b); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return write0600(vaultFile, out.Bytes())
}

func encryptWithPassword(plain []byte, pw, out string) error {
	r, err := age.NewScryptRecipient(pw)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return err
	}
	if _, err = w.Write(plain); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return write0600(out, buf.Bytes())
}

func decryptWithPassword(path, pw string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	id, err := age.NewScryptIdentity(pw)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(b), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func decryptWithIdentity(path string, id age.Identity) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(b), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func decryptArmored(s string, id age.Identity) (string, error) {
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(s)), id)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(r)
	return string(b), err
}

func list(v *Vault) {
	p := append([]Entry(nil), v.Entries...)
	sort.Slice(p, func(i, j int) bool { return strings.ToLower(p[i].Account) < strings.ToLower(p[j].Account) })
	fmt.Printf("%-20s %-20s %-12s %s\n", "account", "username", "password", "last-edited")
	for _, e := range p {
		fmt.Printf("%-20s %-20s %-12s %s\n", e.Account, e.Username, "*********", e.Edited)
	}
	fmt.Println(strings.Repeat("-", 80))
	c := append([]Contact(nil), v.Contacts...)
	sort.Slice(c, func(i, j int) bool { return strings.ToLower(c[i].Name) < strings.ToLower(c[j].Name) })
	fmt.Printf("%-20s %s\n", "contact", "public-key")
	for _, x := range c {
		fmt.Printf("%-20s %s\n", x.Name, x.PubKey)
	}
}

func show(v *Vault, account string) {
	for _, e := range v.Entries {
		if e.Account == account {
			fmt.Println("username:", e.Username)
			fmt.Println("password:", e.Password)
			return
		}
	}
	fmt.Println("not found")
}

func sortVault(v *Vault, mode string) error {
	switch mode {
	case "AZ":
		sort.Slice(v.Entries, func(i, j int) bool { return strings.ToLower(v.Entries[i].Account) < strings.ToLower(v.Entries[j].Account) })
	case "ZA":
		sort.Slice(v.Entries, func(i, j int) bool { return strings.ToLower(v.Entries[i].Account) > strings.ToLower(v.Entries[j].Account) })
	case "Date":
		sort.Slice(v.Entries, func(i, j int) bool { return v.Entries[i].Edited < v.Entries[j].Edited })
	default:
		return errors.New("sort AZ|ZA|Date")
	}
	return nil
}

func addEntry(v *Vault, in *bufio.Reader) error {
	fmt.Print("account: ")
	a, _ := in.ReadString('\n')
	fmt.Print("username: ")
	u, _ := in.ReadString('\n')
	fmt.Print("password: ")
	p, err := readPassword()
	if err != nil {
		return err
	}
	v.Entries = append(v.Entries, Entry{
		Account:  strings.TrimSpace(a),
		Username: strings.TrimSpace(u),
		Password: p,
		Edited:   time.Now().Format("2006-01-02 15:04:05"),
	})
	return nil
}

func editEntry(v *Vault, a string, in *bufio.Reader) error {
	for i := range v.Entries {
		if v.Entries[i].Account == a {
			fmt.Printf("username [%s]: ", v.Entries[i].Username)
			u, _ := in.ReadString('\n')
			fmt.Print("password [hidden, leave blank to keep]: ")
			p, err := readPassword()
			if err != nil {
				return err
			}
			u = strings.TrimSpace(u)
			if u != "" {
				v.Entries[i].Username = u
			}
			if p != "" {
				v.Entries[i].Password = p
			}
			v.Entries[i].Edited = time.Now().Format("2006-01-02 15:04:05")
			return nil
		}
	}
	return errors.New("not found")
}

func delEntry(v *Vault, a string) {
	out := v.Entries[:0]
	for _, e := range v.Entries {
		if e.Account != a {
			out = append(out, e)
		}
	}
	v.Entries = out
}

func addContact(v *Vault, name string, in *bufio.Reader) error {
	fmt.Print("public key: ")
	k, _ := in.ReadString('\n')
	k = strings.TrimSpace(k)
	if name == "" || k == "" {
		return errors.New("contact name and public key required")
	}
	if _, err := age.ParseX25519Recipient(k); err != nil {
		return errors.New("invalid public key")
	}
	for i := range v.Contacts {
		if v.Contacts[i].Name == name {
			v.Contacts[i].PubKey = k
			return nil
		}
	}
	v.Contacts = append(v.Contacts, Contact{Name: name, PubKey: k})
	return nil
}

func delContact(v *Vault, name string) {
	out := v.Contacts[:0]
	for _, c := range v.Contacts {
		if c.Name != name {
			out = append(out, c)
		}
	}
	v.Contacts = out
}

func sendTo(v *Vault, name string, in *bufio.Reader) error {
	var key string
	for _, c := range v.Contacts {
		if c.Name == name {
			key = c.PubKey
			break
		}
	}
	if key == "" {
		return errors.New("contact not found")
	}
	r, err := age.ParseX25519Recipient(key)
	if err != nil {
		return err
	}
	fmt.Printf("Enter your message to %s\n", name)
	msg, _ := in.ReadString('\n')
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		return err
	}
	if _, err = io.WriteString(w, strings.TrimRight(msg, "\r\n")); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	if err = aw.Close(); err != nil {
		return err
	}
	fmt.Println(buf.String())
	return nil
}

func exportVault(v *Vault, in *bufio.Reader, name string) error {
	if name == "" {
		name = defaultExportPath()
	} else {
		name = filepath.Clean(name)
	}

	name = abs(name)
	if !confirm(in, "Export plaintext JSON to "+name+"?") {
		return errors.New("cancelled")
	}

	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		defer f.Close()
		_, err = f.Write(b)
		return err
	}
	if !os.IsExist(err) {
		return err
	}
	if !confirm(in, "File exists. Overwrite "+name+"?") {
		return errors.New("cancelled")
	}
	return write0600(name, b)
}

func defaultExportPath() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "vault.export.json")
	}
	return "vault.export.json"
}

func confirm(in *bufio.Reader, msg string) bool {
	for {
		fmt.Printf("%s [y/N]: ", msg)
		s, err := in.ReadString('\n')
		if err != nil {
			return false
		}
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "y" || s == "yes" {
			return true
		}
		if s == "" || s == "n" || s == "no" {
			return false
		}
	}
}

func readPassword() (string, error) {
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(b), err
}

func clearScreen() {
	fmt.Print("\033[3J\033[H\033[2J")
}

func write0600(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func abs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
