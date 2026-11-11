package picture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math/rand/v2"
	"os"
	"testing"
)

// photo is an opaque w×h image of noise over a gradient, as a photograph is: JPEG encodes it far smaller than PNG.
func photo(w, h int) *image.NRGBA {
	r := rand.New(rand.NewPCG(1, 2))
	m := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			n := uint8(r.IntN(40))
			m.SetNRGBA(x, y, color.NRGBA{uint8(x*255/w) + n, uint8(y*255/h) + n, 90 + n, 255})
		}
	}
	return m
}

func encPNG(t *testing.T, m image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func encJPEG(t *testing.T, m image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, m, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// check processes in and decodes the result, which must be a Size × Size image of type want.
func check(t *testing.T, in []byte, want string) image.Image {
	t.Helper()
	out, typ, err := Process(in)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if typ != want {
		t.Fatalf("type %s, want %s", typ, want)
	}
	var m image.Image
	switch typ {
	case "image/png":
		m, err = png.Decode(bytes.NewReader(out))
	case "image/jpeg":
		m, err = jpeg.Decode(bytes.NewReader(out))
	}
	if err != nil {
		t.Fatalf("the result does not decode as %s: %v", typ, err)
	}
	if b := m.Bounds(); b.Dx() != Size || b.Dy() != Size {
		t.Fatalf("result is %v, want %d×%d", b, Size, Size)
	}
	return m
}

func TestOpaquePhotoBecomesJPEG(t *testing.T) {
	check(t, encPNG(t, photo(640, 480)), "image/jpeg")
	check(t, encJPEG(t, photo(300, 900)), "image/jpeg")
}

func TestTransparencyStaysPNG(t *testing.T) {
	m := photo(300, 300)
	m.SetNRGBA(150, 150, color.NRGBA{1, 2, 3, 128}) // one pixel, in the middle: still seen after scaling
	for y := 140; y < 160; y++ {
		for x := 140; x < 160; x++ {
			m.SetNRGBA(x, y, color.NRGBA{1, 2, 3, 0})
		}
	}
	p := check(t, encPNG(t, m), "image/png")
	if _, _, _, a := p.At(128, 128).RGBA(); a == 0xffff {
		t.Fatal("the transparent middle came out opaque")
	}
}

func TestFlatGraphicMayBePNG(t *testing.T) {
	m := image.NewNRGBA(image.Rect(0, 0, 400, 400))
	for y := range 400 {
		for x := range 400 {
			c := color.NRGBA{20, 80, 200, 255}
			if x > 200 {
				c = color.NRGBA{250, 250, 250, 255}
			}
			m.SetNRGBA(x, y, c)
		}
	}
	check(t, encPNG(t, m), "image/png") // two flat colours: PNG is the smaller
}

func TestWebP(t *testing.T) {
	for file, want := range map[string]string{"testdata/opaque.webp": "", "testdata/alpha.webp": "image/png"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		out, typ, err := Process(b)
		if err != nil || len(out) == 0 {
			t.Fatalf("%s: %v", file, err)
		}
		if want != "" && typ != want {
			t.Fatalf("%s: type %s, want %s", file, typ, want)
		}
	}
}

// withOrientation inserts an EXIF block (APP1, big- or little-endian TIFF) carrying orientation o after a JPEG's SOI.
func withOrientation(j []byte, o uint16, bo binary.AppendByteOrder) []byte {
	tiff := []byte("MM")
	if bo == binary.AppendByteOrder(binary.LittleEndian) {
		tiff = []byte("II")
	}
	tiff = bo.AppendUint16(tiff, 42)
	tiff = bo.AppendUint32(tiff, 8)
	tiff = bo.AppendUint16(tiff, 2) // two entries: another tag first
	tiff = bo.AppendUint16(tiff, 0x010f)
	tiff = bo.AppendUint16(tiff, 2)
	tiff = bo.AppendUint32(tiff, 1)
	tiff = bo.AppendUint32(tiff, 0)
	tiff = bo.AppendUint16(tiff, 0x0112)
	tiff = bo.AppendUint16(tiff, 3)
	tiff = bo.AppendUint32(tiff, 1)
	tiff = bo.AppendUint16(tiff, o)
	tiff = bo.AppendUint16(tiff, 0)
	tiff = bo.AppendUint32(tiff, 0)
	seg := append([]byte("Exif\x00\x00"), tiff...)
	app1 := []byte{0xff, 0xe1}
	app1 = binary.BigEndian.AppendUint16(app1, uint16(len(seg)+2))
	app1 = append(app1, seg...)
	out := append([]byte{}, j[:2]...)
	out = append(out, app1...)
	return append(out, j[2:]...)
}

// isRed reports whether c is mostly red.
func isRed(c color.Color) bool {
	r, g, b, _ := c.RGBA()
	return r > 0xc000 && g < 0x6000 && b < 0x6000
}

func TestEXIFOrientation(t *testing.T) {
	// A square whose top-left quarter is red, the rest blue.
	m := image.NewNRGBA(image.Rect(0, 0, 200, 200))
	for y := range 200 {
		for x := range 200 {
			c := color.NRGBA{20, 40, 220, 255}
			if x < 100 && y < 100 {
				c = color.NRGBA{230, 20, 20, 255}
			}
			m.SetNRGBA(x, y, c)
		}
	}
	j := encJPEG(t, m)
	q := Size / 4
	for _, tc := range []struct {
		o      uint16
		x, y   int // where the red quarter is shown
		endian binary.AppendByteOrder
	}{
		{1, q, q, binary.BigEndian},
		{2, Size - q, q, binary.BigEndian},
		{3, Size - q, Size - q, binary.LittleEndian},
		{4, q, Size - q, binary.BigEndian},
		{5, q, q, binary.LittleEndian},
		{6, Size - q, q, binary.BigEndian}, // turned clockwise: the top-left goes to the top-right
		{7, Size - q, Size - q, binary.BigEndian},
		{8, q, Size - q, binary.LittleEndian}, // anticlockwise: to the bottom-left
	} {
		p := check(t, withOrientation(j, tc.o, tc.endian), "image/jpeg")
		if !isRed(p.At(tc.x, tc.y)) {
			t.Errorf("orientation %d: the red quarter is not at (%d, %d)", tc.o, tc.x, tc.y)
		}
	}
	if exifOrientation(j) != 1 {
		t.Fatal("a JPEG without EXIF reads an orientation")
	}
}

func TestRefused(t *testing.T) {
	big := make([]byte, MaxBytes+1)
	copy(big, encPNG(t, photo(10, 10)))
	var g bytes.Buffer
	_ = gif.Encode(&g, photo(20, 20), nil)
	// A PNG header that declares a 9000-pixel-wide image: refused from its header, before anything is decoded.
	wide := encPNG(t, image.NewNRGBA(image.Rect(0, 0, 9000, 1)))
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"too many bytes": {big, ErrTooLarge},
		"gif":            {g.Bytes(), ErrFormat},
		"svg":            {[]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), ErrFormat},
		"junk":           {[]byte("hello, this is not an image"), ErrFormat},
		"empty":          {nil, ErrFormat},
		"truncated png":  {encPNG(t, photo(50, 50))[:60], ErrDecode},
		"broken jpeg":    {append([]byte{0xff, 0xd8, 0xff, 0xe0}, bytes.Repeat([]byte{1}, 40)...), ErrDecode},
		"too wide":       {wide, ErrDimensions},
	} {
		if _, _, err := Process(tc.in); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestOutputCarriesNoMetadata(t *testing.T) {
	j := withOrientation(encJPEG(t, photo(100, 100)), 1, binary.BigEndian)
	out, _, err := Process(j)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("Exif")) {
		t.Fatal("the EXIF block was kept")
	}
}
