import rollupNodeResolve from "rollup-plugin-node-resolve";

export default {
  format: "iife",
  moduleName: "bundle",
  entry: "es6.js",
  dest: "bundle.js",
  plugins: [
    rollupNodeResolve({ jsnext: true, main: true })
  ]
};