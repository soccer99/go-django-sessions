"""Test the actual standalone examples without adding frameworks to the library module.
Run: python3 testdata/test_frameworks.py
"""
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
frameworks = {
    "stdlib": None,
    "chi": "github.com/go-chi/chi/v5@v5.2.3",
    "gorilla": "github.com/gorilla/mux@v1.8.1",
    "httprouter": "github.com/julienschmidt/httprouter@v1.3.0",
    "gin": "github.com/gin-gonic/gin@v1.11.0",
    "echo": "github.com/labstack/echo/v4@v4.13.4",
    "fiber": "github.com/gofiber/fiber/v2@v2.52.9",
    "fiber_v3": "github.com/gofiber/fiber/v3@v3.0.0",
}
for name, dependency in frameworks.items():
    print("Testing " + name, flush=True)
    with tempfile.TemporaryDirectory(prefix="django-framework-") as directory:
        work = pathlib.Path(directory)
        subprocess.run(["go", "mod", "init", "example.com/framework-test"], cwd=work, check=True)
        subprocess.run(["go", "mod", "edit", "-replace", "github.com/soccer99/go-django-sessions=" + str(root)], cwd=work, check=True)
        source = (root / "examples" / (name + ".go")).read_text().replace("//go:build ignore", "")
        (work / "example.go").write_text(source)
        test = (root / "testdata/frameworks_test.go.txt").read_text()
        if name.startswith("fiber"):
            test = test.replace('    "net/http/httptest"', '    "net/http/httptest"\n    "io"')
            request = """response, err := buildRouter(auth).Test(req)
            if err != nil { t.Fatal(err) }
            defer response.Body.Close()
            rawBody, err := io.ReadAll(response.Body)
            if err != nil { t.Fatal(err) }
            status, body := response.StatusCode, string(rawBody)"""
        else:
            request = """recorder := httptest.NewRecorder()
            buildRouter(auth).ServeHTTP(recorder, req)
            status, body := recorder.Code, recorder.Body.String()"""
        (work / "example_test.go").write_text(test.replace("// FRAMEWORK_REQUEST", request))
        dependencies = ["github.com/soccer99/go-django-sessions"]
        if dependency:
            dependencies.append(dependency)
        subprocess.run(["go", "get", *dependencies], cwd=work, check=True)
        subprocess.run(["go", "test", "-race", "./..."], cwd=work, check=True)
