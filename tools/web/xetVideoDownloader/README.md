## xetVideoDownloader

"小*通" Video Downloader, This tool requires the 'ffmpeg' command.
- Support live playback of videos.
- Support encrypted videos.

## Usage

1. Find the m3u8 URL

Open the DevTools in chrome (or another browser that has Devtools) and filter the 'm3u8' character to find the URL for m3u8. You must copy the URL in full or it will not pass authentication.

2. Download Video

```bash
xetVideoDownloader -u 'https://xxxx.m3u8?xxxx' -o out.ts
```
