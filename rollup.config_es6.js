import rollupIncludePaths from "rollup-plugin-includepaths";
import rollupNodeResolve from "rollup-plugin-node-resolve";

export default {
    format: "iife",
    plugins: [
        rollupIncludePaths({
            paths: ["src"]
        }),
        rollupNodeResolve({ jsnext: true, main: true })
    ]
};
