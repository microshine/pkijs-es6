import babel from 'rollup-plugin-babel';
import rollupNodeResolve from "rollup-plugin-node-resolve";

export default {
  format: "iife",
  moduleName: "bundle",
  plugins: [
    rollupNodeResolve({ jsnext: true, main: true }),
    babel({
      "presets": ["es2015-rollup"]
    })
  ]
};