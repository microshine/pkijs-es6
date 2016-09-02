/**
 * Created by L on 02.09.16.
 */

import babel from 'rollup-plugin-babel';
import rollupNodeResolve from "rollup-plugin-node-resolve";

export default {
  format: "iife",
  moduleName: "bundle",
  entry: "es6.js",
  dest: "bundle.js",
  plugins: [
    babel({
      "presets": ["es2015-rollup"]
    }),
    rollupNodeResolve({ jsnext: true, main: true })
  ]
};