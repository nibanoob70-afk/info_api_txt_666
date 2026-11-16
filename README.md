# RAFIN TxT - Free Fire Info API

## Endpoints
- `/` - service information
- `/health` - health check
- `/status` - token/configuration diagnostics (does not expose passwords or tokens)
- `/info?uid=PLAYER_UID` - player information

## Required Vercel environment variables
Set these in Vercel Project Settings -> Environment Variables:
- `BD_UID`
- `BD_PASSWORD`
- `IND_UID`
- `IND_PASSWORD`
- `BR_UID`
- `BR_PASSWORD`

Optional:
- `JWT_API_BASE` (defaults to `https://jwt-wxun.vercel.app/token`)
- `FF_RELEASE_VERSION` (defaults to `OB55`; set to a version supported by the upstream service)

Do not commit account passwords to GitHub. Rotate any credentials that were previously published.

## Local run
Install `requirements.txt`, set the environment variables, then run `python app.py`.
