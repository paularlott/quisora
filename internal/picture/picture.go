// Package picture makes the profile picture of a user from an image as it is given: a JPEG, PNG or WebP of at most
// MaxBytes and MaxSide pixels a side, turned upright (a JPEG's EXIF orientation), cropped to its centre square and
// scaled to Size pixels a side. The result is always encoded afresh: nothing of the original (metadata such as a
// photo's location, or anything a file shaped to be read as two formats carries) reaches what is stored and served.
package picture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"io"

	"golang.org/x/image/draw"
	"golang.org/x/image/webp"
)

const (
	// MaxBytes is the largest image accepted.
	MaxBytes = 5 << 20
	// MaxSide is the widest and tallest image accepted: an image is decoded whole, so its size in pixels, not in
	// bytes, is what it costs (a small file can declare a huge image).
	MaxSide = 8192
	// Size is the width and height of every picture made.
	Size = 256
	// jpegQuality is the quality an opaque picture is encoded at when JPEG is the smaller.
	jpegQuality = 80
)

// The refusals of Process. Their messages are written for whoever chose the image.
var (
	ErrTooLarge   = errors.New("the image is larger than 5 MB")
	ErrFormat     = errors.New("use a JPEG, PNG or WebP image")
	ErrDimensions = errors.New("the image is too large: at most 8192 pixels wide and tall")
	ErrDecode     = errors.New("the image could not be read")
)

// slots bounds the images decoded at once on this node to one: the largest accepted (8192×8192, 16 bits a channel)
// takes about 512 MB while it is, and pictures change rarely enough that the next one waits its turn.
var slots = make(chan struct{}, 1)

// format is an image format Process reads.
type format struct {
	config func(io.Reader) (image.Config, error)
	decode func(io.Reader) (image.Image, error)
	exif   bool // may carry an EXIF orientation (JPEG)
}

var (
	jpegFormat = format{jpeg.DecodeConfig, jpeg.Decode, true}
	pngFormat  = format{png.DecodeConfig, png.Decode, false}
	webpFormat = format{webp.DecodeConfig, webp.Decode, false}
)

// sniff names b's format by its first bytes; ok is false for anything but JPEG, PNG and WebP. Each format's own
// decoder is called: image.Decode would take any format registered in the program (GIF, for one).
func sniff(b []byte) (format, bool) {
	switch {
	case bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}):
		return jpegFormat, true
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return pngFormat, true
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return webpFormat, true
	}
	return format{}, false
}

// Process makes a picture of b: it returns the picture's bytes and their content type, image/png when any pixel is
// not fully opaque, else whichever of JPEG (quality 80) and PNG is the smaller.
func Process(b []byte) ([]byte, string, error) {
	if len(b) > MaxBytes {
		return nil, "", ErrTooLarge
	}
	f, ok := sniff(b)
	if !ok {
		return nil, "", ErrFormat
	}
	cfg, err := f.config(bytes.NewReader(b))
	if err != nil {
		return nil, "", ErrDecode
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > MaxSide || cfg.Height > MaxSide {
		return nil, "", ErrDimensions
	}
	slots <- struct{}{}
	src, err := f.decode(bytes.NewReader(b))
	var pic *image.RGBA
	if err == nil {
		pic = square(src)
	}
	<-slots
	if err != nil {
		return nil, "", ErrDecode
	}
	if f.exif {
		pic = orient(pic, exifOrientation(b))
	}
	return encode(pic)
}

// square scales the centre square of src to Size × Size.
func square(src image.Image) *image.RGBA {
	r := src.Bounds()
	side := min(r.Dx(), r.Dy())
	x0, y0 := r.Min.X+(r.Dx()-side)/2, r.Min.Y+(r.Dy()-side)/2
	dst := image.NewRGBA(image.Rect(0, 0, Size, Size))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, image.Rect(x0, y0, x0+side, y0+side), draw.Src, nil)
	return dst
}

// encode encodes p: PNG when it is not fully opaque, else the smaller of JPEG and PNG.
func encode(p *image.RGBA) ([]byte, string, error) {
	var pb bytes.Buffer
	if err := png.Encode(&pb, p); err != nil {
		return nil, "", err
	}
	if !p.Opaque() {
		return pb.Bytes(), "image/png", nil
	}
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, p, &jpeg.Options{Quality: jpegQuality}); err != nil {
		return nil, "", err
	}
	if jb.Len() < pb.Len() {
		return jb.Bytes(), "image/jpeg", nil
	}
	return pb.Bytes(), "image/png", nil
}

// orient turns the square p as EXIF orientation o (1 to 8) says the image is to be shown. Cropping to the centre
// square and scaling commute with each of these turns and mirrors, so they are applied to the small picture.
func orient(p *image.RGBA, o int) *image.RGBA {
	if o < 2 || o > 8 {
		return p
	}
	n := p.Bounds().Dx()
	out := image.NewRGBA(p.Bounds())
	for y := range n {
		for x := range n {
			sx, sy := x, y
			switch o {
			case 2: // mirrored
				sx = n - 1 - x
			case 3: // turned 180°
				sx, sy = n-1-x, n-1-y
			case 4: // mirrored upside down
				sy = n - 1 - y
			case 5: // transposed
				sx, sy = y, x
			case 6: // to be turned 90° clockwise
				sx, sy = y, n-1-x
			case 7: // transversed
				sx, sy = n-1-y, n-1-x
			case 8: // to be turned 90° anticlockwise
				sx, sy = n-1-y, x
			}
			si, di := p.PixOffset(sx, sy), out.PixOffset(x, y)
			copy(out.Pix[di:di+4], p.Pix[si:si+4])
		}
	}
	return out
}

// exifOrientation reads the orientation tag of a JPEG's EXIF block (APP1): 1 (as stored) when there is none or it
// cannot be read.
func exifOrientation(b []byte) int {
	i := 2 // after SOI
	for i+4 <= len(b) {
		if b[i] != 0xff {
			return 1
		}
		marker := b[i+1]
		if marker == 0xff { // fill byte
			i++
			continue
		}
		if marker == 0xda || marker == 0xd9 { // start of scan, end of image: no more metadata
			return 1
		}
		n := int(binary.BigEndian.Uint16(b[i+2:]))
		if n < 2 || i+2+n > len(b) {
			return 1
		}
		if seg := b[i+4 : i+2+n]; marker == 0xe1 && bytes.HasPrefix(seg, []byte("Exif\x00\x00")) {
			return tiffOrientation(seg[6:])
		}
		i += 2 + n
	}
	return 1
}

// tiffOrientation reads tag 0x0112 of the first IFD of a TIFF structure (an EXIF block's body).
func tiffOrientation(t []byte) int {
	if len(t) < 8 {
		return 1
	}
	var bo binary.ByteOrder
	switch string(t[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return 1
	}
	if bo.Uint16(t[2:]) != 42 {
		return 1
	}
	off := int(bo.Uint32(t[4:]))
	if off < 8 || off+2 > len(t) {
		return 1
	}
	count := int(bo.Uint16(t[off:]))
	for e := off + 2; count > 0 && e+12 <= len(t); e, count = e+12, count-1 {
		if bo.Uint16(t[e:]) == 0x0112 && bo.Uint16(t[e+2:]) == 3 { // orientation, a SHORT
			if v := int(bo.Uint16(t[e+8:])); v >= 1 && v <= 8 {
				return v
			}
			return 1
		}
	}
	return 1
}
