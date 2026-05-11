# Architecture — Project 04: Password Strength Analyzer

## Scoring Algorithm

```
Pool size = sum of character-class sizes present in password
  (lower=26, upper=26, digits=10, special=32)

Entropy = password_length × log₂(pool_size)  [bits]

Base score (0–4):
  entropy ≥ 80 AND length ≥ 16  →  4 (Very Strong)
  entropy ≥ 60                   →  3 (Strong)
  entropy ≥ 40                   →  2 (Fair)
  entropy ≥ 20                   →  1 (Weak)
  else                           →  0 (Very Weak)

Penalty: −1 per warning (keyboard walks, dates, repeats), minimum 0
```

## Limitations

Naive entropy assumes an adversary doesn't know the password's character-class
composition. Real-world cracking uses dictionaries and Markov models. For a more
realistic score, integrate `zxcvbn-python` (see CLAUDE.md tech stack).
