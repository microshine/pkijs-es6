import rollupNodeResolve from "rollup-plugin-node-resolve";

export default {
  format: "iife",
  moduleName: "bundle",
  plugins: [
    rollupNodeResolve({ jsnext: true, main: true })
  ]
};