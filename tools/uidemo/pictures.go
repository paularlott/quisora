package main

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// seedPictures gives users profile pictures made here, through the same processing as an upload: the first a
// transparent PNG (a circle), the others opaque gradient photos (JPEG), each in a hue of its own.
func seedPictures(ctx context.Context, svc *service.Service, users ...*model.User) {
	for i, u := range users {
		raw := gradientJPEG(i)
		if i == 0 {
			raw = circlePNG()
		}
		img, err := service.MakePicture(ctx, raw, service.HashSource(raw))
		must(err)
		_, err = svc.UpdateUser(ctx, service.System, u.ID, service.UserInput{Picture: &service.PictureChange{Image: img}})
		must(err)
	}
}

// gradientJPEG is a 480×360 photo-like JPEG: a diagonal gradient between two colours that depend on n.
func gradientJPEG(n int) []byte {
	a := []color.NRGBA{{29, 78, 216, 255}, {190, 18, 60, 255}, {4, 120, 87, 255}, {180, 83, 9, 255}, {109, 40, 217, 255}}[n%5]
	b := color.NRGBA{250, 204, 21, 255}
	if n%2 == 1 {
		b = color.NRGBA{14, 165, 233, 255}
	}
	const w, h = 480, 360
	m := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			t := float64(x+y) / float64(w+h)
			mix := func(p, q uint8) uint8 { return uint8(float64(p) + t*(float64(q)-float64(p))) }
			m.SetNRGBA(x, y, color.NRGBA{mix(a.R, b.R), mix(a.G, b.G), mix(a.B, b.B), 255})
		}
	}
	var buf bytes.Buffer
	must(jpeg.Encode(&buf, m, &jpeg.Options{Quality: 90}))
	return buf.Bytes()
}

// circlePNG is a 300×300 PNG of a filled circle on a transparent background.
func circlePNG() []byte {
	const s = 300
	m := image.NewNRGBA(image.Rect(0, 0, s, s))
	for y := range s {
		for x := range s {
			if dx, dy := x-s/2, y-s/2; dx*dx+dy*dy <= (s/2-10)*(s/2-10) {
				m.SetNRGBA(x, y, color.NRGBA{13, 148, 136, 255})
			}
		}
	}
	var buf bytes.Buffer
	must(png.Encode(&buf, m))
	return buf.Bytes()
}
