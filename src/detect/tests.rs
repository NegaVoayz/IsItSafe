    use super::*;

    #[test]
    fn rejects_fake_mz() {
        assert!(!is_pe(b"MZ"));
        let mut bytes = vec![0u8; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(!is_pe(&bytes));
    }

    #[test]
    fn finds_trailing_zip() {
        let mut zip_bytes = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_bytes);
            zip.start_file("payload.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zip, b"trailing content").unwrap();
            zip.finish().unwrap();
        }
        let head = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
        let mut tail = b"\0\0\0\0IEND\xaeB`\x82".to_vec();
        tail.extend_from_slice(zip_bytes.get_ref());
        let total_size = (head.len() + tail.len()) as u64;
        let result = sniff(Path::new("photo.png"), head, &tail, total_size);
        assert!(
            result
                .classification
                .formats
                .iter()
                .any(|f| f.kind == "zip")
        );
        assert!(result.classification.risky_trailing_data);
    }

    #[test]
    fn zip_member_headers_are_not_treated_as_embedded_archives() {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("first.txt", options).unwrap();
            std::io::Write::write_all(&mut zip, b"first").unwrap();
            zip.start_file("second.rar", options).unwrap();
            std::io::Write::write_all(&mut zip, b"Rar!\x1A\x07\x01\x00").unwrap();
            zip.finish().unwrap();
        }

        let hits = scan_all(bytes.get_ref());
        assert!(!hits.iter().any(|hit| hit.kind == "zip" && hit.offset > 0));
    }

    #[test]
    fn all_local_headers_of_a_valid_zip_belong_to_the_outer_archive() {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            for index in 0..40 {
                let options = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated);
                zip.start_file(format!("ppt/slides/slide{index}.xml"), options)
                    .unwrap();
                std::io::Write::write_all(
                    &mut zip,
                    format!("<p:sld><a:t>{index}</a:t></p:sld>").as_bytes(),
                )
                .unwrap();
            }
            zip.finish().unwrap();
        }

        let hits = scan_all(bytes.get_ref());
        assert!(!hits.iter().any(|hit| hit.kind == "zip"));
    }

    #[test]
    fn pdf_stream_payload_is_not_mistaken_for_embedded_formats() {
        let mut pdf = b"%PDF-1.7\n1 0 obj\n<< /Length 17 >>\nstream\n".to_vec();
        pdf.extend_from_slice(b"random /JS PK\x03\x04 bytes");
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF");

        let hits = scan_all(&pdf);
        assert!(hits.is_empty());
    }

    #[test]
    fn finds_zip_appended_outside_pdf_stream_data() {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            zip.start_file("payload.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zip, b"hello").unwrap();
            zip.finish().unwrap();
        }
        let mut pdf = b"%PDF-1.7\n".to_vec();
        pdf.extend_from_slice(bytes.get_ref());
        pdf.extend_from_slice(b"\n%%EOF");

        let hits = scan_all(&pdf);
        assert!(
            hits.iter().any(|hit| hit.kind == "zip" && hit.offset > 0),
            "hits={hits:?}, streams={:?}",
            pdf_stream_ranges(&pdf)
        );
    }

    #[test]
    fn office_relationship_extensions_are_recognized_as_text() {
        assert!(!extension_mismatch("rels", "unknown"));
    }

    #[test]
    fn unknown_content_does_not_make_a_generic_extension_suspicious() {
        assert!(!extension_mismatch("dat", "unknown"));
        assert!(!extension_mismatch("resources", "unknown"));
    }

    #[test]
    fn known_extensions_still_detect_contradictory_content() {
        assert!(extension_mismatch("jpg", "pe"));
        assert!(extension_mismatch("pdf", "zip"));
        assert!(extension_mismatch("zip", "pe"));
    }

    #[test]
    fn validates_webp_riff_header_without_an_extension_mismatch() {
        let webp = b"RIFF\x04\0\0\0WEBP";
        let result = sniff(Path::new("comic.webp"), webp, webp, webp.len() as u64);
        assert!(
            result
                .classification
                .formats
                .iter()
                .any(|format| format.kind == "webp")
        );
        assert!(!result.classification.extension_mismatch);
        assert!(!result.classification.risky_trailing_data);
    }
