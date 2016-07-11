import rollupIncludePaths from "rollup-plugin-includepaths";
import rollupNodeResolve from "rollup-plugin-node-resolve";
import rollupBabel from "rollup-plugin-babel";

export default {
	format: "iife",
	plugins: [
		rollupIncludePaths({
			paths: ["src"]
		}),
		rollupNodeResolve({ jsnext: true, main: true }),
		rollupBabel({
			compact: "false",
			presets: ["es2015-rollup"]
		})
	]
};
