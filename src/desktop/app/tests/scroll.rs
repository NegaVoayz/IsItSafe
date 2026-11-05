    use super::*;

    fn viewport() -> egui::Rect {
        egui::Rect::from_min_max(egui::pos2(200.0, 100.0), egui::pos2(980.0, 700.0))
    }

    #[test]
    fn scrollbar_stays_hidden_away_from_the_right_edge() {
        let now = Instant::now();
        assert!(!scrollbar_should_reveal(
            viewport(),
            Some(egui::pos2(500.0, 300.0)),
            None,
            now
        ));
    }

    #[test]
    fn scrollbar_reveals_near_the_right_edge() {
        assert!(scrollbar_should_reveal(
            viewport(),
            Some(egui::pos2(960.0, 300.0)),
            None,
            Instant::now()
        ));
    }

    #[test]
    fn scrollbar_reveals_briefly_after_scrolling() {
        let now = Instant::now();
        assert!(scrollbar_should_reveal(
            viewport(),
            Some(egui::pos2(500.0, 300.0)),
            Some(now - Duration::from_millis(200)),
            now
        ));
        assert!(!scrollbar_should_reveal(
            viewport(),
            Some(egui::pos2(500.0, 300.0)),
            Some(now - SCROLLBAR_REVEAL_AFTER_SCROLL),
            now
        ));
    }
