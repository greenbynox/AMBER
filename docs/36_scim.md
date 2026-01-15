# SCIM v2 (Users & Groups)

## Auth
Utiliser un token SCIM :
- `POST /orgs/:id/scim-token` (admin)
- Header : `Authorization: Bearer <token>`

## Users
- `GET /scim/v2/Users`
- `POST /scim/v2/Users`
- `GET /scim/v2/Users/:id`
- `PUT /scim/v2/Users/:id`
- `DELETE /scim/v2/Users/:id`

Payload minimal :
```
{
  "userName": "user@acme.tld",
  "active": true
}
```

## Groups
- `GET /scim/v2/Groups`
- `POST /scim/v2/Groups`
- `GET /scim/v2/Groups/:id`
- `PUT /scim/v2/Groups/:id`
- `DELETE /scim/v2/Groups/:id`

Payload minimal :
```
{
  "displayName": "Team Platform",
  "members": [{ "value": "<user_uuid>" }]
}
```

## Notes
- Les users SCIM sont reliés à l’organisation via `org_users`.
- Les membres d’un groupe remplacent la liste existante (reset complet).
