# Repo Shapes

This repo already contains the IDS object shapes that the first version of this skill is built around.

## Usage policy example

The preconfiguration guide shows a generated IDS permission with:

- `@type: ids:Permission`
- `ids:action: USE`

See:

- `/Users/akiskourtis/Documents/github/IDS-testbed/PreparingPreconfiguredSetup.md`

## Contract negotiation example

The Postman flow sends a permission list into:

- `POST /api/ids/contract`

and later resolves agreement artifacts before obtaining data.

See:

- `/Users/akiskourtis/Documents/github/IDS-testbed/TestbedPreconfiguration.postman_collection.json`

## Agreement example

The preconfiguration guide includes a contract agreement carrying:

- `ids:permission`
- `ids:assignee`
- `ids:assigner`
- `ids:target`
- `ids:contractStart`
- `ids:contractEnd`

Those fields are the main reason this first skill version can produce more concrete guidance for agreement objects than for standalone permissions.

## Connector security profile

Both sample connectors in this repo use:

- `idsc:BASE_SECURITY_PROFILE`

See:

- `/Users/akiskourtis/Documents/github/IDS-testbed/DataspaceConnectorA/conf/config.json`
- `/Users/akiskourtis/Documents/github/IDS-testbed/DataspaceConnectorB/conf/config.json`

That means the skill should default to narrow agent capabilities and avoid widening tool access just because the IDS object exists.
