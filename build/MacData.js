"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _DigestInfo = require("./DigestInfo");

var _DigestInfo2 = _interopRequireDefault(_DigestInfo);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var MacData = function () {
	//**********************************************************************************
	/**
  * Constructor for MacData class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function MacData() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, MacData);

		//region Internal properties of the object
		/**
   * @type {DigestInfo}
   * @description mac
   */
		this.mac = (0, _pvutils.getParametersValue)(parameters, "mac", MacData.defaultValues("mac"));
		/**
   * @type {OctetString}
   * @description macSalt
   */
		this.macSalt = (0, _pvutils.getParametersValue)(parameters, "macSalt", MacData.defaultValues("macSalt"));

		if ("iterations" in parameters)
			/**
    * @type {number}
    * @description iterations
    */
			this.iterations = (0, _pvutils.getParametersValue)(parameters, "iterations", MacData.defaultValues("iterations"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(MacData, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, MacData.schema({
				names: {
					mac: {
						names: {
							blockName: "mac"
						}
					},
					macSalt: "macSalt",
					iterations: "iterations"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for MacData");
			//endregion

			//region Get internal properties from parsed schema
			this.mac = new _DigestInfo2.default({ schema: asn1.result.mac });
			this.macSalt = asn1.result.macSalt;

			if ("iterations" in asn1.result) this.iterations = asn1.result.iterations.valueBlock.valueDec;
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Construct and return new ASN.1 schema for this object
			var outputArray = [this.mac.toSchema(), this.macSalt];

			if ("iterations" in this) outputArray.push(new asn1js.Integer({ value: this.iterations }));

			return new asn1js.Sequence({
				value: outputArray
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			var output = {
				mac: this.mac.toJSON(),
				macSalt: this.macSalt.toJSON()
			};

			if ("iterations" in this) output.iterations = this.iterations.toJSON();

			return output;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "mac":
					return new _DigestInfo2.default();
				case "macSalt":
					return new asn1js.OctetString();
				case "iterations":
					return 1;
				default:
					throw new Error("Invalid member name for MacData class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */

	}, {
		key: "compareWithDefault",
		value: function compareWithDefault(memberName, memberValue) {
			switch (memberName) {
				case "mac":
					return _DigestInfo2.default.compareWithDefault("digestAlgorithm", memberValue.digestAlgorithm) && _DigestInfo2.default.compareWithDefault("digest", memberValue.digest);
				case "macSalt":
					return memberValue.isEqual(MacData.defaultValues(memberName));
				case "iterations":
					return memberValue === MacData.defaultValues(memberName);
				default:
					throw new Error("Invalid member name for MacData class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//MacData ::= SEQUENCE {
			//    mac 		DigestInfo,
			//    macSalt       OCTET STRING,
			//    iterations	INTEGER DEFAULT 1
			//    -- Note: The default is for historical reasons and its use is
			//    -- deprecated. A higher value, like 1024 is recommended.
			//    }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [optional]
    * @property {string} [mac]
    * @property {string} [macSalt]
    * @property {string} [iterations]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				optional: names.optional || true,
				value: [_DigestInfo2.default.schema(names.mac || {
					names: {
						blockName: "mac"
					}
				}), new asn1js.OctetString({ name: names.macSalt || "macSalt" }), new asn1js.Integer({
					optional: true,
					name: names.iterations || "iterations"
				})]
			});
		}
	}]);

	return MacData;
}();
//**************************************************************************************


exports.default = MacData;
//# sourceMappingURL=MacData.js.map