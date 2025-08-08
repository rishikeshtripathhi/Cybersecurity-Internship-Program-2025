import unicodedata
import difflib


homoglyph_map = {
    'а': 'a',  # Cyrillic a
    'е': 'e',  # Cyrillic e
    'і': 'i',  # Cyrillic i
    'о': 'o',  # Cyrillic o
    'ѕ': 's',  # Cyrillic s
    'ɡ': 'g',  # Latin script g
    'ӏ': 'l',  # Cyrillic small letter palochka
    'ꞯ': 'm',  # Latin small turned m
    'ᴜ': 'u',  # Modifier letter small u
    'ϲ': 'c',  # Greek small letter lunate sigma
    'ρ': 'p',  # Greek rho
    'ñ': 'n',  # Tilde n
    # Add more if needed
}


whitelist = [
    "google.com",
    "facebook.com",
    "youtube.com",
    "instagram.com",
    "amazon.com",
    "apple.com",
    "microsoft.com",
    "netflix.com",
    "whatsapp.com",
    "twitter.com"
]


def normalize_domain(domain):
    normalized = ""
    for char in domain:
        normalized += homoglyph_map.get(char, char)
    return unicodedata.normalize('NFKC', normalized)


def is_suspicious(input_domain, whitelist):
    normalized = normalize_domain(input_domain)
    close_matches = difflib.get_close_matches(normalized, whitelist, n=1, cutoff=0.8)
    return close_matches, normalized


def main():
    print("Homoglyph (Homographic) Domain Detector")
    print("----------------------------------------")
    user_input = input("Enter a domain name to check: ").strip()

    similar_domains, normalized_version = is_suspicious(user_input, whitelist)

    print(f"\nNormalized domain: {normalized_version}")

    if user_input != normalized_version and similar_domains:
        print(f"⚠️  Suspicious domain detected!")
        print(f"Looks similar to: {similar_domains[0]}")
    elif user_input == normalized_version:
        print("✅ Domain appears safe. No suspicious characters detected.")
    else:
        print("ℹ️ Domain has unusual characters, but no close match found.")


# Run the program
if __name__ == "__main__":
    main()
