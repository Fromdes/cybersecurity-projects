# Architecture — ABAC Policy Engine

## Components

```
cli.py    Click CLI (evaluate / dump / init-policy)
core.py   Condition, PolicyRule, ABACEngine, AttributeSet, Decision dataclasses
```

## Data Model

```
AttributeSet(attrs: dict)   ← subject / resource / environment

Condition
  namespace: subject | resource | environment
  attribute: string
  operator: eq | neq | in | not_in | gt | gte | lt | lte | contains | matches
  value: any

PolicyRule
  name, effect (permit|deny), priority, conditions: list[Condition]

ABACEngine
  rules: list[PolicyRule]  (sorted by priority desc)
  combining: deny-overrides | permit-overrides | first-applicable
```

## Evaluation Flow

```
evaluate(subject, resource, environment)
  1. Filter rules: rule.matches() = all conditions satisfied
  2. Apply combining algorithm:
     deny-overrides:    any DENY → DENY; else first PERMIT
     permit-overrides:  any PERMIT → PERMIT; else first DENY
     first-applicable:  highest-priority matching rule wins
  3. No match → DENY (default closed)
```

## Policy Format

```yaml
combining_algorithm: deny-overrides
rules:
  - name: deny-external-sensitive
    effect: deny
    priority: 100
    conditions:
      - attribute: subject.location
        operator: eq
        value: external
      - attribute: resource.classification
        operator: eq
        value: sensitive
```
