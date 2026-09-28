# Sterahi fork direction

This repository begins as an upstream-compatible fork of SuggestArr. It is a
separate household media discovery, recommendation, request, and automation
application—not a Brigid widget surface or a replacement for the Brigid home
page.

## Product boundary

- **Brigid:** lightweight household home page and navigation.
- **This application:** media discovery, recommendation generation, user
  feedback, request review, automation policy, and media-library workflow.
- Brigid may link to this application, but neither product depends on the
  other's internal API or deployment lifecycle.

## Non-negotiable security model

- Pocket ID will become the identity authority through native OIDC.
- Service credentials, media-server tokens, Seerr credentials, and AI-provider
  keys remain server-side.
- Browser storage must not hold service secrets or OIDC client secrets.
- Administrator access derives from verified identity-provider group claims.
- Existing local-account behavior stays available only as a controlled
  transitional migration path, not the final account authority.

## Upstream policy

- `origin` is the Sterahi/ChillDryad fork.
- `upstream` remains `giuseppe99barchetta/SuggestArr`.
- Keep upstream integration, job, and provider fixes easy to adopt by isolating
  fork-specific work behind adapters and small feature areas.
- Review each upstream release deliberately; cherry-pick or merge only after
  tests and migration review.

## First implementation milestones

1. Establish a reproducible local/Portainer deployment that uses a Sterahi
   image namespace and persistent configuration paths.
2. Add native Pocket ID authorization-code + PKCE authentication with opaque
   server-side sessions and an account migration plan.
3. Replace local-account authorization decisions with verified OIDC identity
   and groups while preserving media-profile links.
4. Make user feedback and request-review workflows first-class household
   features: interested, not now, watched, disliked, already available, and
   explicit request/approval states.
5. Add a stable notification/outbox boundary for request results, job failures,
   and curated recommendation digests.

## Explicitly deferred

- Brigid embedding or shared frontend components.
- A broad visual rewrite before authentication, migrations, and workflow tests
  are stable.
- Automated destructive media cleanup without a visible review/audit path.
