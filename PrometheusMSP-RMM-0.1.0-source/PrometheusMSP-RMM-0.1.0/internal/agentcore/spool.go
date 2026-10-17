package agentcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type SpoolItem struct {
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}
type Spool struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
}

func NewSpool(dir string, maxBytes int64) (*Spool, error) {
	if maxBytes < 1 {
		return nil, errors.New("max spool bytes must be positive")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	return &Spool{dir: dir, maxBytes: maxBytes}, nil
}

func (s *Spool) Enqueue(kind string, value any) error {
	if kind == "" || strings.ContainsAny(kind, `/\\`) {
		return errors.New("invalid spool kind")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	item, err := json.Marshal(SpoolItem{Kind: kind, Body: body})
	if err != nil {
		return err
	}
	if int64(len(item)) > s.maxBytes {
		return errors.New("item exceeds spool capacity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name := fmt.Sprintf("%020d-%08x.json", time.Now().UnixNano(), randomUint32())
	if err := os.WriteFile(filepath.Join(s.dir, name), item, 0600); err != nil {
		return err
	}
	return s.trimLocked()
}

func (s *Spool) Drain(send func(SpoolItem) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.filesLocked()
	if err != nil {
		return err
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(s.dir, f.Name()))
		if err != nil {
			return err
		}
		var item SpoolItem
		if err := json.Unmarshal(b, &item); err != nil {
			_ = os.Rename(filepath.Join(s.dir, f.Name()), filepath.Join(s.dir, f.Name()+".bad"))
			continue
		}
		if err := send(item); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(s.dir, f.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (s *Spool) Depth() int { s.mu.Lock(); defer s.mu.Unlock(); f, _ := s.filesLocked(); return len(f) }
func (s *Spool) trimLocked() error {
	f, e := s.filesLocked()
	if e != nil {
		return e
	}
	var total int64
	for _, x := range f {
		total += x.Size()
	}
	for total > s.maxBytes && len(f) > 0 {
		total -= f[0].Size()
		if e = os.Remove(filepath.Join(s.dir, f[0].Name())); e != nil {
			return e
		}
		f = f[1:]
	}
	return nil
}
func (s *Spool) filesLocked() ([]os.FileInfo, error) {
	es, e := os.ReadDir(s.dir)
	if e != nil {
		return nil, e
	}
	var fs []os.FileInfo
	for _, x := range es {
		if strings.HasSuffix(x.Name(), ".json") {
			i, e := x.Info()
			if e != nil {
				return nil, e
			}
			fs = append(fs, i)
		}
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].Name() < fs[j].Name() })
	return fs, nil
}

func randomUint32() uint32 {
	var b [4]byte
	_, _ = randRead(b[:])
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
