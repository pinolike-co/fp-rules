기준 SBOM — 공개 컨테이너 이미지로 만든 CycloneDX JSON 만 둔다. 고객·사내 서버 SBOM 은 넣지 않는다.

    syft <이미지> -o cyclonedx-json > corpus/<이름>.json
