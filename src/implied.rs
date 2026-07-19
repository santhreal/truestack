//! Implied technology detection  -  infer invisible technologies from visible ones.
//!
//! When you detect React in the HTML, you KNOW the build pipeline includes
//! webpack/babel/Node.js. When you detect Spring Boot, you KNOW Java + Tomcat.
//! This gives downstream vulnerability scanners 3x more targets to check.
//!
//! The implication graph is directional: detecting A implies B exists.

use crate::{TechCategory, Technology};

/// An implication rule: if technology A is detected, technology B is implied.
struct Implication {
    /// Name of the detected technology (trigger).
    trigger: &'static str,
    /// Technologies implied by the trigger.
    implied: &'static [(&'static str, TechCategory)],
}

const IMPLICATIONS: &[Implication] = &[
    // Frontend frameworks → build tools
    Implication {
        trigger: "React",
        implied: &[
            ("webpack", TechCategory::Framework),
            ("Node.js", TechCategory::Language),
            ("babel", TechCategory::Framework),
        ],
    },
    Implication {
        trigger: "Next.js",
        implied: &[
            ("React", TechCategory::Framework),
            ("Node.js", TechCategory::Language),
            ("webpack", TechCategory::Framework),
        ],
    },
    Implication {
        trigger: "Vue.js",
        implied: &[
            ("webpack", TechCategory::Framework),
            ("Node.js", TechCategory::Language),
        ],
    },
    Implication {
        trigger: "Angular",
        implied: &[
            ("TypeScript", TechCategory::Language),
            ("Node.js", TechCategory::Language),
            ("webpack", TechCategory::Framework),
        ],
    },
    Implication {
        // The fingerprint rule (in rules.toml) registers Nuxt as
        // "Nuxt.js"  -  this trigger has to match that exact canonical
        // name or the implied chain (Nuxt.js → Vue.js → Node.js)
        // silently never fires.
        trigger: "Nuxt.js",
        implied: &[
            ("Vue.js", TechCategory::Framework),
            ("Node.js", TechCategory::Language),
        ],
    },
    // Backend frameworks → runtimes
    Implication {
        trigger: "Spring Boot",
        implied: &[
            ("Java", TechCategory::Language),
            ("Tomcat", TechCategory::Server),
        ],
    },
    Implication {
        trigger: "Django",
        implied: &[("Python", TechCategory::Language)],
    },
    Implication {
        trigger: "Flask",
        implied: &[("Python", TechCategory::Language)],
    },
    Implication {
        trigger: "Rails",
        implied: &[
            ("Ruby", TechCategory::Language),
            ("Puma", TechCategory::Server),
        ],
    },
    Implication {
        trigger: "Laravel",
        implied: &[("PHP", TechCategory::Language)],
    },
    Implication {
        trigger: "Express",
        implied: &[("Node.js", TechCategory::Language)],
    },
    Implication {
        trigger: "ASP.NET",
        implied: &[
            ("C#", TechCategory::Language),
            ("IIS", TechCategory::Server),
        ],
    },
    Implication {
        trigger: "Gin",
        implied: &[("Go", TechCategory::Language)],
    },
    Implication {
        trigger: "FastAPI",
        implied: &[
            ("Python", TechCategory::Language),
            ("uvicorn", TechCategory::Server),
        ],
    },
    // CMS → backend
    Implication {
        trigger: "WordPress",
        implied: &[
            ("PHP", TechCategory::Language),
            ("MySQL", TechCategory::Database),
        ],
    },
    Implication {
        trigger: "Drupal",
        implied: &[("PHP", TechCategory::Language)],
    },
    Implication {
        trigger: "Magento",
        implied: &[
            ("PHP", TechCategory::Language),
            ("MySQL", TechCategory::Database),
            ("Elasticsearch", TechCategory::Database),
        ],
    },
    // CDN → implies origin server exists
    Implication {
        trigger: "Cloudflare",
        implied: &[], // Cloudflare is a proxy, doesn't imply specific origin
    },
    // Databases exposed in headers
    Implication {
        trigger: "Redis",
        implied: &[], // Redis is standalone
    },
];

/// Expand a set of detected technologies with implied technologies.
///
/// Returns the ADDITIONAL technologies inferred  -  the caller should merge
/// these with the original set, deduplicating by name.
pub fn expand(detected: &[Technology]) -> Vec<Technology> {
    let detected_names: std::collections::HashSet<&str> =
        detected.iter().map(|t| t.name.as_str()).collect();

    let mut implied = Vec::new();
    let mut implied_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    for tech in detected {
        for rule in IMPLICATIONS {
            if tech.name.eq_ignore_ascii_case(rule.trigger) {
                for &(name, ref category) in rule.implied {
                    if !detected_names.contains(name) && implied_names.insert(name.to_string()) {
                        implied.push(Technology {
                            name: name.to_string(),
                            version: None,
                            category: category.clone(),
                            // Implied technologies get lower confidence
                            confidence: (tech.confidence / 2).max(20),
                        });
                    }
                }
            }
        }
    }

    implied
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tech(name: &str, cat: TechCategory) -> Technology {
        Technology {
            name: name.into(),
            version: None,
            category: cat,
            confidence: 90,
        }
    }

    #[test]
    fn react_implies_nodejs_webpack() {
        let detected = vec![tech("React", TechCategory::Framework)];
        let implied = expand(&detected);
        let names: Vec<&str> = implied.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"Node.js"));
        assert!(names.contains(&"webpack"));
    }

    #[test]
    fn spring_boot_implies_java_tomcat() {
        let detected = vec![tech("Spring Boot", TechCategory::Framework)];
        let implied = expand(&detected);
        let names: Vec<&str> = implied.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(names.contains(&"Tomcat"));
    }

    #[test]
    fn no_duplicates_when_already_detected() {
        let detected = vec![
            tech("React", TechCategory::Framework),
            tech("Node.js", TechCategory::Language),
        ];
        let implied = expand(&detected);
        // Node.js already detected, should not appear in implied
        assert!(!implied.iter().any(|t| t.name == "Node.js"));
    }

    #[test]
    fn implied_confidence_is_lower() {
        let detected = vec![tech("React", TechCategory::Framework)];
        let implied = expand(&detected);
        for t in &implied {
            assert!(
                t.confidence <= 45,
                "{} confidence too high: {}",
                t.name,
                t.confidence
            );
        }
    }
}
