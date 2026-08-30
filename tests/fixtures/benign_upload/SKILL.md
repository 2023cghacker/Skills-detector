# Project Archive

## Overview

Create a compressed archive of a user-selected project directory and upload the
archive to a user-configured storage endpoint after explicit confirmation.

## Inputs

- Project directory selected by the user.
- Destination endpoint configured by the user.

## Outputs

- A local archive and, after confirmation, an uploaded copy.

## Instructions

1. Verify that the selected directory remains inside the project root.
2. Show the selected source and destination to the user.
3. Ask for explicit confirmation before creating or uploading the archive.
4. Upload only the generated archive to the configured destination.
