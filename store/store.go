package store

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

var (
	NoStore = errors.New("not in store")
)

type data struct {
	value int64
	isp   string
}

type Store struct {
	m map[int64]*data
	l []int64
}

func NewStore() *Store {
	s := &Store{}
	s.m = make(map[int64]*data)
	s.l = make([]int64, 0)
	return s

}

func (self *Store) Load(fi *os.File) {
	buf := bufio.NewReader(fi)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			continue
		}
		content := strings.TrimSpace(line)
		contens := strings.Split(content, "#")
		detail := strings.Split(contens[1], ":")
		isp := detail[len(detail)-1]
		start, _ := strconv.Atoi(contens[0])
		value, _ := strconv.Atoi(detail[1])
		d := &data{}
		d.isp = isp
		d.value = int64(value)
		self.m[int64(start)] = d
		self.l = append(self.l, int64(start))
	}
	return

}

func (self *Store) ipToInt(ip string) int64 {
	bits := strings.Split(ip, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	var sum int64
	sum += int64(b0) << 24
	sum += int64(b1) << 16
	sum += int64(b2) << 8
	sum += int64(b3)
	return sum
}

func (self *Store) Get(ip string) (string, error) {
	if len(self.l) > 0 {
		ip64 := self.ipToInt(ip)
		index := self.binarySearh(ip64)
		if index == -1 {
			return "", NoStore
		} else {
			data := self.m[self.l[index]]
			value := data.value
			if self.l[index]+value >= ip64 {
				return data.isp, nil
			}
		}
	}
	return "", NoStore
}

func (self *Store) binarySearh(ip int64) int {
	left := 0
	right := len(self.l) - 1
	for left <= right {
		middle := left + ((right - left) >> 1)
		if self.l[middle] > ip {
			right = middle - 1 //right赋值，适时而变
		} else if self.l[middle] < ip {
			left = middle + 1
		} else {
			return middle
		}

	}
	return right

}
