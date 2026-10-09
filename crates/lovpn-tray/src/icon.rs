//! The tray icon drawn in code, so no image file is shipped and any size works.
//!
//! Each state has its own *shape* inside a coloured disc, not only its own colour: a check
//! (protected), an exclamation mark (incomplete or unknown), a cross (blocked), a dash (not
//! connected), three dots (connecting) and a slash (service down).
use crate::model::Key;

/// Premultiplied BGRA pixels (`0xAARRGGBB` per `u32`), `size` x `size`, top row first.
pub fn pixels(key: Key, size: usize) -> Vec<u32> {
    let disc = match key {
        Key::Protected => (0x1b, 0x6f, 0x4f),
        Key::Connecting => (0x2f, 0x5f, 0xa8),
        Key::Disconnected => (0x5b, 0x63, 0x6b),
        Key::Degraded | Key::Unknown => (0xa8, 0x62, 0x00),
        Key::Blocked | Key::Service => (0xb0, 0x2a, 0x2a),
    };
    let mut out = vec![0u32; size * size];
    let n = size as f32;
    for y in 0..size {
        for x in 0..size {
            // Unit square coordinates, pixel centres.
            let (u, v) = ((x as f32 + 0.5) / n, (y as f32 + 0.5) / n);
            let radius = ((u - 0.5).powi(2) + (v - 0.5).powi(2)).sqrt();
            let coverage = ((0.48 - radius) * n).clamp(0.0, 1.0);
            if coverage <= 0.0 {
                continue;
            }
            let glyph = (glyph_coverage(key, u, v, n) * coverage).clamp(0.0, 1.0);
            let mix = |d: u8| (f32::from(d) * (1.0 - glyph) + 255.0 * glyph) * coverage;
            let alpha = (coverage * 255.0).round() as u32;
            out[y * size + x] = (alpha << 24)
                | ((mix(disc.0).round() as u32) << 16)
                | ((mix(disc.1).round() as u32) << 8)
                | mix(disc.2).round() as u32;
        }
    }
    out
}

fn segment_distance(p: (f32, f32), a: (f32, f32), b: (f32, f32)) -> f32 {
    let (ab, ap) = ((b.0 - a.0, b.1 - a.1), (p.0 - a.0, p.1 - a.1));
    let len2 = ab.0 * ab.0 + ab.1 * ab.1;
    let t = if len2 == 0.0 {
        0.0
    } else {
        ((ap.0 * ab.0 + ap.1 * ab.1) / len2).clamp(0.0, 1.0)
    };
    ((p.0 - a.0 - t * ab.0).powi(2) + (p.1 - a.1 - t * ab.1).powi(2)).sqrt()
}

fn glyph_coverage(key: Key, u: f32, v: f32, n: f32) -> f32 {
    let p = (u, v);
    let stroke = 0.075;
    let near = |d: f32, w: f32| ((w - d) * n).clamp(0.0, 1.0);
    let line = |a, b| near(segment_distance(p, a, b), stroke);
    let dot = |c: (f32, f32), r: f32| near(((u - c.0).powi(2) + (v - c.1).powi(2)).sqrt(), r);
    match key {
        Key::Protected => line((0.29, 0.52), (0.44, 0.66)).max(line((0.44, 0.66), (0.72, 0.35))),
        Key::Degraded | Key::Unknown => line((0.5, 0.26), (0.5, 0.57)).max(dot((0.5, 0.72), 0.06)),
        Key::Blocked => line((0.32, 0.32), (0.68, 0.68)).max(line((0.68, 0.32), (0.32, 0.68))),
        Key::Disconnected => line((0.3, 0.5), (0.7, 0.5)),
        Key::Connecting => dot((0.3, 0.5), 0.065)
            .max(dot((0.5, 0.5), 0.065))
            .max(dot((0.7, 0.5), 0.065)),
        Key::Service => line((0.3, 0.7), (0.7, 0.3)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Key; 7] = [
        Key::Service,
        Key::Protected,
        Key::Connecting,
        Key::Disconnected,
        Key::Degraded,
        Key::Blocked,
        Key::Unknown,
    ];

    #[test]
    fn every_state_is_drawn_at_every_size_with_clear_corners_and_a_solid_centre() {
        for size in [16, 20, 24, 32, 48] {
            for key in ALL {
                let p = pixels(key, size);
                assert_eq!(p.len(), size * size);
                assert_eq!(p[0] >> 24, 0, "{key:?}/{size}: corners are transparent");
                assert_eq!(p[size * size - 1] >> 24, 0);
                let centre = p[(size / 2) * size + size / 2];
                assert!(centre >> 24 >= 0xf0, "{key:?}/{size}: centre is opaque");
            }
        }
    }

    #[test]
    fn states_differ_in_shape_not_only_in_colour() {
        // Compare the white glyph mask, ignoring the disc colour.
        let mask = |key| -> Vec<bool> {
            pixels(key, 32)
                .into_iter()
                .map(|px| (px & 0xff) > 0xe0 && ((px >> 8) & 0xff) > 0xe0)
                .collect()
        };
        let masks: Vec<_> = ALL.iter().map(|k| mask(*k)).collect();
        for i in 0..ALL.len() {
            assert!(masks[i].iter().any(|b| *b), "{:?} has a glyph", ALL[i]);
            for j in (i + 1)..ALL.len() {
                // Degraded and unknown share a glyph and colour by design: both mean "look".
                if matches!((ALL[i], ALL[j]), (Key::Degraded, Key::Unknown)) {
                    continue;
                }
                assert!(
                    masks[i] != masks[j],
                    "{:?} and {:?} look alike",
                    ALL[i],
                    ALL[j]
                );
            }
        }
    }
}
