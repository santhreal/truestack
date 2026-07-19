use super::*;
use crate::TechCategory;

#[test]
fn detect_ubuntu_from_server_header() {
    let headers = vec![("Server".to_string(), "Apache/2.4.41 (Ubuntu)".to_string())];
    let os = detect_os(&headers);
    assert!(os.is_some());
    let ctx = os.unwrap();
    assert_eq!(ctx.distro, Distro::Ubuntu);
    assert!(ctx.distro.backports_patches());
}

#[test]
fn detect_debian_from_php_version() {
    let headers = vec![(
        "X-Powered-By".to_string(),
        "PHP/7.4.33-1+deb11u1".to_string(),
    )];
    let os = detect_os(&headers);
    assert!(os.is_some());
    let ctx = os.unwrap();
    assert_eq!(ctx.distro, Distro::Debian);
    assert_eq!(ctx.version_hint.as_deref(), Some("Debian 11"));
}

#[test]
fn detect_rhel_from_el_suffix() {
    let headers = vec![("X-Powered-By".to_string(), "PHP/5.4.16-48.el7".to_string())];
    let os = detect_os(&headers);
    assert!(os.is_some());
    let ctx = os.unwrap();
    assert_eq!(ctx.distro, Distro::Rhel);
    assert_eq!(ctx.version_hint.as_deref(), Some("EL7"));
}

#[test]
fn no_os_from_clean_headers() {
    let headers = vec![("Server".to_string(), "nginx/1.21.0".to_string())];
    let os = detect_os(&headers);
    assert!(os.is_none());
}

#[test]
fn assess_backported_version() {
    let techs = vec![Technology {
        name: "Apache".to_string(),
        version: Some("2.4.41".to_string()),
        category: TechCategory::Server,
        confidence: 95,
    }];
    let headers = vec![("Server".to_string(), "Apache/2.4.41 (Ubuntu)".to_string())];
    let assessments = assess_headers(&techs, &headers);

    assert_eq!(assessments.len(), 1);
    let a = &assessments[0];
    assert!(a.backport_likely);
    assert_eq!(a.reliability, VersionReliability::Unreliable);
    assert!(a.advisory.contains("backport"));
    assert!(a.advisory.contains("Do NOT"));
}

#[test]
fn assess_rolling_release() {
    let techs = vec![Technology {
        name: "nginx".to_string(),
        version: Some("1.25.0".to_string()),
        category: TechCategory::Server,
        confidence: 95,
    }];
    // Simulate detecting Arch Linux from fingerprinting
    let headers = vec![("Server".to_string(), "nginx/1.25.0 Arch".to_string())];
    let assessments = assess_headers(&techs, &headers);

    let a = &assessments[0];
    assert!(!a.backport_likely);
    assert_eq!(a.reliability, VersionReliability::Likely);
}

#[test]
fn assess_no_version_technology() {
    let techs = vec![Technology {
        name: "Cloudflare".to_string(),
        version: None,
        category: TechCategory::Cdn,
        confidence: 95,
    }];
    let headers: Vec<(String, String)> = vec![];
    let assessments = assess_headers(&techs, &headers);

    assert_eq!(assessments[0].reliability, VersionReliability::NoVersion);
}

#[test]
fn assess_inline_debian_version() {
    // PHP version string itself contains the Debian suffix
    let techs = vec![Technology {
        name: "PHP".to_string(),
        version: Some("7.4.33-1+deb11u1".to_string()),
        category: TechCategory::Language,
        confidence: 85,
    }];
    // No OS in server header  -  should detect from version string itself
    let headers = vec![("Server".to_string(), "nginx/1.18.0".to_string())];
    let assessments = assess_headers(&techs, &headers);

    let a = &assessments[0];
    assert!(a.backport_likely);
    assert_eq!(a.reliability, VersionReliability::Unreliable);
    assert!(a.os_context.is_some());
    assert_eq!(a.os_context.as_ref().unwrap().distro, Distro::Debian);
}

#[test]
fn distro_backport_classification() {
    assert!(Distro::Debian.backports_patches());
    assert!(Distro::Ubuntu.backports_patches());
    assert!(Distro::Rhel.backports_patches());
    assert!(Distro::CentOs.backports_patches());
    assert!(Distro::AmazonLinux.backports_patches());
    assert!(Distro::Suse.backports_patches());
    assert!(!Distro::Arch.backports_patches());
    assert!(!Distro::Fedora.backports_patches());
    assert!(!Distro::Alpine.backports_patches());
    assert!(Distro::Arch.is_rolling());
    assert!(Distro::Fedora.is_rolling());
    assert!(!Distro::Debian.is_rolling());
}
