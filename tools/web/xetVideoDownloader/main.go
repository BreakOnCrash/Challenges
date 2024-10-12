/*
build:

	CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o bin/xetVideoDownloader main.go
*/
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tmpDir for download ts files...
const tmpDirPrefix = "tmp-tss-%d"

var keyUrlRex = regexp.MustCompile(`AES-128,URI="(.*?)"`)
var numRex = regexp.MustCompile(`(\d+)`)

func parseM3u8(url string) ([]string, []byte, error) {
	var key []byte

	res, err := request(url)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	ret := make([]string, 0)
	i := strings.LastIndex(url, "/")
	if i == -1 {
		return nil, nil, errors.New("unable to obtain URL prefix")
	}
	prefix := url[:i+1]

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		line := scanner.Text()
		// 获取密钥
		if strings.Contains(line, "EXT-X-KEY") {
			data := keyUrlRex.FindStringSubmatch(line)
			if len(data) >= 2 {
				res, err := request(data[1])
				if err != nil {
					return nil, nil, err
				}
				defer res.Body.Close()
				if res.StatusCode == 200 {
					key, err = io.ReadAll(res.Body)
					if err != nil {
						return nil, nil, err
					}
				}
			}
		}
		if strings.Contains(line, ".ts") {
			ret = append(ret, prefix+strings.TrimSpace(line))
		}
	}

	return ret, key, nil
}

type taskItem struct {
	index int
	url   string
}

func downloadTS(urls []string) (string, error) {
	tmp := fmt.Sprintf(tmpDirPrefix, time.Now().Unix())
	if err := os.MkdirAll(tmp, os.ModePerm); err != nil {
		return tmp, err
	}

	var wg sync.WaitGroup
	queue := make(chan taskItem)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(queue)
		i := 0
		for _, item := range urls {
			i++
			queue <- taskItem{
				index: i,
				url:   item,
			}
		}
	}()

	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			for {
				task, ok := <-queue
				if !ok {
					break
				}

				res, err := request(task.url)
				if err != nil {
					fmt.Printf("download ts url:%s error:%s\n", task.url, err)
					continue
				}
				defer res.Body.Close()

				file := path.Join(tmp, fmt.Sprintf("%d.ts", task.index))
				f, err := os.Create(file)
				if err != nil {
					fmt.Printf("open file:%s error:%s\n", file, err)
					continue
				}
				defer f.Close()

				if _, err := io.Copy(f, res.Body); err != nil {
					fmt.Printf("copy to file:%s error:%s\n", file, err)
					continue
				}
			}
		}()
	}

	wg.Wait()
	return tmp, nil
}

func combineWithFfmpeg(dirpath string, out string) error {
	files, err := getDirFiles(dirpath)
	if err != nil {
		return err
	}

	cmd := exec.Command("ffmpeg", "-i", fmt.Sprintf("concat:%s", strings.Join(files, "|")), "-c", "copy", out)
	_, e := cmd.CombinedOutput()
	return e
}

func decryptFile(dirpath string, key []byte) error {
	fs, err := os.ReadDir(dirpath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	for _, e := range fs {
		if strings.HasSuffix(e.Name(), ".ts") {
			data, err := os.ReadFile(filepath.Join(dirpath, e.Name()))
			if err != nil {
				return err
			}

			pt := make([]byte, len(data))
			bm := cipher.NewCBCDecrypter(block, bytes.Repeat([]byte{0}, 16))
			bm.CryptBlocks(pt, data)
			if err = os.WriteFile(filepath.Join(dirpath, e.Name()), pt, 0755); err != nil {
				return err
			}
		}
	}

	return nil
}

type fileWithNum struct {
	Name string
	Num  int
}

func getDirFiles(dirpath string) ([]string, error) {
	files := make([]fileWithNum, 0)

	fs, err := os.ReadDir(dirpath)
	if err != nil {
		return nil, err
	}

	for _, e := range fs {
		if strings.HasSuffix(e.Name(), ".ts") {
			match := numRex.FindStringSubmatch(e.Name())
			if len(match) > 1 {
				num, err := strconv.Atoi(match[1])
				if err == nil {
					files = append(files, fileWithNum{e.Name(), num})
				}
			}
		}
	}

	// 按照数字部分进行排序
	sort.Slice(files, func(i, j int) bool {
		return files[i].Num < files[j].Num
	})

	ret := make([]string, 0)
	for _, f := range files {
		ret = append(ret, filepath.Join(dirpath, f.Name))
	}

	return ret, nil
}

func request(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x6304051b)")
	req.Header.Set("Origin", "https://appli0n8byd8759.h5.xiaoeknow.com")
	req.Header.Set("Referer", "https://appli0n8byd8759.h5.xiaoeknow.com/")
	return http.DefaultClient.Do(req)
}

func main() {
	var url string
	var output string

	flag.StringVar(&url, "u", "", "m3u8 url")
	flag.StringVar(&output, "o", "out.ts", "output file")
	flag.Parse()

	if url == "" {
		fmt.Println("must input m3u8 url")
		return
	}

	// check ffmpeg command
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		fmt.Println("not found the 'ffmpeg' command")
		return
	}

	fmt.Println("parse m3u8 link")
	urls, key, err := parseM3u8(url)
	if err != nil {
		fmt.Println("parse m3u8 error:", err)
		return
	}

	fmt.Printf("download %d ts files...\n", len(urls))
	tmpDir, err := downloadTS(urls)
	if err != nil {
		fmt.Println("download ts files error:", err)
		return
	}

	if key != nil {
		fmt.Println("decrypt ts files...")
		if err := decryptFile(tmpDir, key); err != nil {
			fmt.Println("decrypt ts files error:", err)
			return
		}
	}

	fmt.Println("combine ts files...")
	if err := combineWithFfmpeg(tmpDir, output); err != nil {
		fmt.Println("combine ts files error:", err)
		return
	}

	// 移除临时文件
	os.RemoveAll(tmpDir)

	fmt.Println("download success ", output)
}
