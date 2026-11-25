"""Authenticated, same-origin Swagger UI and the live API schema."""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response

from hst.app.auth import current_user

router = APIRouter(dependencies=[Depends(current_user)], include_in_schema=False)


@router.get("/docs", response_class=HTMLResponse)
async def swagger_ui() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HST API</title>
<link rel="stylesheet" href="./docs-assets/swagger-ui.css">
</head><body><div id="swagger-ui"></div>
<script src="./docs-assets/swagger-ui-bundle.js"></script>
<script src="./docs-init.js"></script></body></html>"""


@router.get("/docs-init.js")
async def swagger_init() -> Response:
    return Response(
        """SwaggerUIBundle({
  url: './openapi.json',
  dom_id: '#swagger-ui',
  deepLinking: true,
  validatorUrl: null,
  queryConfigEnabled: false,
  supportedSubmitMethods: ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'],
  requestInterceptor: function(request) {
    request.credentials = 'same-origin';
    request.headers['X-HST-CSRF'] = '1';
    return request;
  }
});""",
        media_type="application/javascript",
    )


@router.get("/docs-assets/{filename}")
async def swagger_asset(request: Request, filename: str) -> FileResponse:
    if filename not in {"swagger-ui.css", "swagger-ui-bundle.js"}:
        raise HTTPException(404)
    path = request.app.state.settings.web_dist / "swagger-ui" / filename
    if not path.is_file():
        raise HTTPException(
            503, detail="API documentation assets missing; run npm ci and npm run build in web/"
        )
    return FileResponse(path)


@router.get("/openapi.json")
async def openapi_schema(request: Request) -> dict:
    return request.app.openapi()
