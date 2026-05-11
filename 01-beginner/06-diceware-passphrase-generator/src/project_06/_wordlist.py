"""Bundled demo wordlist (256 common English words).

For production use, replace with the full EFF Large Wordlist (7776 words):
    https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt

Entropy with this list: log2(256) = 8.0 bits/word
Entropy with EFF large: log2(7776) ≈ 12.9 bits/word
"""

DEMO_WORDLIST: tuple[str, ...] = (
    "able", "acid", "aged", "also", "area", "army", "away", "baby",
    "back", "ball", "band", "bank", "base", "bath", "bear", "beat",
    "been", "bell", "best", "bill", "bird", "blow", "blue", "bold",
    "bond", "bone", "book", "bore", "born", "both", "bowl", "burn",
    "busy", "call", "calm", "came", "card", "care", "cart", "case",
    "cash", "cast", "cave", "cell", "chat", "chip", "city", "clam",
    "clap", "clay", "clip", "club", "clue", "coal", "coat", "code",
    "coin", "cold", "colt", "come", "cook", "cool", "cope", "copy",
    "cord", "core", "corn", "cost", "coup", "crew", "crop", "cure",
    "curl", "damp", "dare", "dark", "data", "dawn", "days", "dead",
    "deal", "dear", "deck", "deed", "deep", "deny", "desk", "dial",
    "dice", "dine", "disk", "dive", "dock", "does", "dome", "door",
    "dose", "dove", "down", "draw", "drip", "drop", "drum", "dual",
    "dull", "dump", "dusk", "dust", "duty", "each", "earn", "ease",
    "east", "edge", "else", "emit", "epic", "even", "ever", "exam",
    "exit", "face", "fact", "fade", "fail", "fair", "fall", "fame",
    "farm", "fast", "fate", "fear", "feed", "feel", "feet", "fell",
    "felt", "file", "fill", "film", "find", "fine", "fire", "firm",
    "fish", "fist", "flag", "flat", "flew", "flip", "flow", "foam",
    "fold", "folk", "fond", "font", "food", "fool", "foot", "ford",
    "fork", "form", "fort", "foul", "four", "free", "from", "fuel",
    "full", "fund", "fuse", "gain", "game", "gate", "gave", "gear",
    "gift", "glad", "glow", "glue", "goal", "goes", "gold", "golf",
    "gone", "good", "grab", "gray", "grew", "grid", "grip", "grow",
    "gulf", "gust", "half", "hall", "halt", "hand", "hang", "hard",
    "harm", "hash", "haze", "head", "heal", "heap", "heat", "heel",
    "held", "helm", "help", "hero", "hide", "high", "hill", "hint",
    "hire", "hold", "hole", "home", "hood", "hook", "hope", "horn",
    "host", "hour", "hunt", "hurt", "idea", "idle", "inch", "into",
    "iron", "isle", "item", "join", "joke", "jump", "just", "keen",
    "keep", "kick", "kind", "king", "knee", "knew", "knot", "know",
)
